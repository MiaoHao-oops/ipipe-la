// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2020, Jianmin Lv <lvjianmin@loongson.cn>
 *  Loongson Extend I/O Interrupt Vector support
 */

#define pr_fmt(fmt) "extioi: " fmt

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/syscore_ops.h>
#include <asm/irq_cpu.h>

#ifndef CONFIG_SMP
#define cpu_logical_map(cpu)	(0)
#endif

#define VEC_COUNT_PER_REG	64
#define MAX_EIO_NODES (NR_CPUS / CORES_PER_EXTIOI_NODE)

struct extioi {
	u32		vec_count;
	u32		misc_func;
	u32		eio_en_off;
	struct irq_domain	*extioi_domain;
	struct fwnode_handle	*domain_handle;
	nodemask_t		node_map;
	u32		node;
	struct cpumask cpuspan_map;
} *extioi_priv[MAX_EIO_PICS];

int nr_extioi;

unsigned int extioi_en[IOCSR_EXTIOI_VECTOR_NUM/32];

struct fwnode_handle *eiointc_get_fwnode(int id)
{
	return extioi_priv[id]->domain_handle;
}

int eiointc_get_node(int id)
{
	return extioi_priv[id]->node;
}

static void virt_extioi_set_irq_route(int pos, unsigned int cpu)
{
	iocsr_writeb(cpu_logical_map(cpu), LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE + pos);
}

static int group_of_node(int node)
{
	int i;
	for (i = 0; i < nr_extioi; i++) {
		if (node_isset(node, extioi_priv[i]->node_map))
			return i;
	}
	return -1;
}

static int cpu_to_eio_node(int cpu)
{
	return cpu_logical_map(cpu) / CORES_PER_EXTIOI_NODE;
}

static void extioi_set_irq_route(int pos, unsigned int cpu, nodemask_t *node_map, unsigned int on_node)
{
	uint32_t pos_off;
	unsigned int node, dst_node, route_node;
	unsigned char coremap[MAX_EIO_NODES];
	uint32_t data, data_byte, data_mask;
	unsigned int cpu_iter;

	pos_off = pos & ~3;
	data_byte = pos & (3);
	data_mask = ~BIT_MASK(data_byte) & 0xf;
	memset(coremap, 0, sizeof(unsigned char) * MAX_EIO_NODES);

	/* calculate dst node and coremap of target irq */
	dst_node = cpu_to_eio_node(cpu);
	coremap[dst_node] |= (1 << (cpu_logical_map(cpu) %
				CORES_PER_EXTIOI_NODE));

	for_each_online_cpu(cpu_iter) {
		node = cpu_to_eio_node(cpu_iter);
		if (node_isset(node, *node_map)) {
			data = 0ULL;

			/* extioi node 0 is in charge of inter-node interrupt dispatch */
			route_node = (node == on_node) ? dst_node : node;
			data |= ((coremap[node] | (route_node << 4))
				<< (data_byte * 8));
			csr_any_send(LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE + pos_off, data, data_mask, node * CORES_PER_EXTIOI_NODE);
		}
	}
}

static DEFINE_SPINLOCK(affinity_lock);

int ext_set_irq_affinity(struct irq_data *d, const struct cpumask *affinity,
			  bool force)
{
	uint32_t vector, pos_off;
	unsigned long flags;
	unsigned int cpu;
	struct extioi *priv = (struct extioi *)d->domain->host_data;
	struct cpumask intersect_affinity;

	if (!IS_ENABLED(CONFIG_SMP))
		return -EPERM;

	spin_lock_irqsave(&affinity_lock, flags);
	if (!cpumask_intersects(affinity, cpu_online_mask)) {
		spin_unlock_irqrestore(&affinity_lock, flags);
		return -EINVAL;
	}

	cpumask_and(&intersect_affinity, affinity, cpu_online_mask);
	cpumask_and(&intersect_affinity, &intersect_affinity, &priv->cpuspan_map);
	if (cpumask_empty(&intersect_affinity)) {
		spin_unlock_irqrestore(&affinity_lock, flags);
		return -EINVAL;
	}
	cpu = cpumask_first(&intersect_affinity);

	/*
	 * control interrupt enable or disalbe through cpu 0
	 * which is reponsible for dispatching interrupts.
	 */
	vector = d->hwirq;
	pos_off = vector >> 5;

	if (cpu_has_hypervisor) {
		iocsr_writel(extioi_en[pos_off] & (~((1 << (vector & 0x1F)))),
				LOONGARCH_IOCSR_EXTIOI_EN_BASE + (pos_off << 2));
		virt_extioi_set_irq_route(vector, cpu);
		iocsr_writel(extioi_en[pos_off],
			LOONGARCH_IOCSR_EXTIOI_EN_BASE + (pos_off << 2));
	} else {
		csr_any_send(LOONGARCH_IOCSR_EXTIOI_EN_BASE + (pos_off << 2),
				extioi_en[pos_off] &
				(~((1 << (vector & 0x1F)))), 0x0, 0);
		extioi_set_irq_route(vector, cpu, &priv->node_map, priv->node);
		csr_any_send(LOONGARCH_IOCSR_EXTIOI_EN_BASE + (pos_off << 2),
				extioi_en[pos_off], 0x0, 0);
	}

	irq_data_update_effective_affinity(d, cpumask_of(cpu));
	spin_unlock_irqrestore(&affinity_lock, flags);

	return IRQ_SET_MASK_OK;
}

/* Initializing a extioi controller */
void extioi_init(void)
{
	int i, j;
	uint32_t data;
	uint64_t tmp;

	int extioi_node = cpu_to_eio_node(smp_processor_id());
	int group = group_of_node(extioi_node);

	if (group < 0) {
		pr_err("Error: no node map for extioi group!\n");
		return;
	}
	/* init irq en bitmap */
	if (extioi_node == 0) {
		for (i = 0; i < IOCSR_EXTIOI_VECTOR_NUM/32; i++)
			extioi_en[i] = -1;
	}

	/* Only the first cpu of a extioi node initializes this extioi controller */
	if (smp_processor_id() % CORES_PER_EXTIOI_NODE == 0) {
		if (!extioi_priv[0]->misc_func) {
			tmp = iocsr_readq(LOONGARCH_IOCSR_MISC_FUNC)
			| IOCSR_MISC_FUNC_EXT_IOI_EN;
			iocsr_writeq(tmp, LOONGARCH_IOCSR_MISC_FUNC);
		} else {
			tmp = iocsr_readq(extioi_priv[0]->misc_func) | (1 << extioi_priv[0]->eio_en_off);
			iocsr_writeq(tmp, extioi_priv[0]->misc_func);
		}

		for (j = 0; j < 8; j++) {
			data = (((1 << (j*2 + 1)) << 16) | (1 << (j*2)));
			iocsr_writel(data,
				LOONGARCH_IOCSR_EXTIOI_NODEMAP_BASE + j*4);
		}

		for (j = 0; j < 2; j++) {
			data = (1 << (1 + group)) | ((1 << (1 + group)) << 8) |
				((1 << (1 + group)) << 16) | ((1 << (1 + group)) << 24);

			iocsr_writel(data, LOONGARCH_IOCSR_EXTIOI_IPMAP_BASE + j*4);
		}

		for (j = 0; j < IOCSR_EXTIOI_VECTOR_NUM/4; j++) {
			if (!group) {
				if (cpu_has_hypervisor) {
					tmp = cpu_logical_map(0);
				} else {
					tmp = BIT(cpu_logical_map(0));
				}

				/* route to node 0 logical core 0 */
				data = tmp | (tmp << 8) | (tmp << 16) | (tmp << 24);
				iocsr_writel(data, LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE + j*4);
			} else {

				/* route to node connected to bridge */
				tmp = (extioi_priv[group]->node << 4) | 1;
				data = tmp | (tmp << 8) | (tmp << 16) | (tmp << 24);
				iocsr_writel(data, LOONGARCH_IOCSR_EXTIOI_ROUTE_BASE + j*4);
			}
		}

		for (j = 0; j < IOCSR_EXTIOI_VECTOR_NUM/32; j++) {
			data = -1;
			iocsr_writel(data, LOONGARCH_IOCSR_EXTIOI_BOUNCE_BASE + j*4);
			iocsr_writel(data, LOONGARCH_IOCSR_EXTIOI_EN_BASE + j*4);
		}
	}
}

static void extioi_irq_dispatch(struct irq_desc *desc)
{
	int i;
	u64 pending;
	bool handled = false;
	struct irq_chip *chip = irq_desc_get_chip(desc);
	struct extioi *priv = irq_desc_get_handler_data(desc);
	int reg_count;
	chained_irq_enter(chip, desc);

	reg_count = priv->vec_count >> 6;

	for (i = 0; i < reg_count; i++) {
		pending = iocsr_readq(LOONGARCH_IOCSR_EXTIOI_ISR_BASE + (i << 3));
		/* Do not write ISR register since it is zero already */
		if (pending == 0)
			continue;

		iocsr_writeq(pending, LOONGARCH_IOCSR_EXTIOI_ISR_BASE + (i << 3));

		while (pending) {
			int bit = __ffs(pending);
			int virq = irq_linear_revmap(priv->extioi_domain,
					bit + VEC_COUNT_PER_REG * i);
			if (virq > 0)
				ipipe_handle_demuxed_irq(virq);
			pending &= ~BIT(bit);
			handled = true;
		}
	}

	if (!handled)
		spurious_interrupt();

	chained_irq_exit(chip, desc);
}

static void extioi_ack_irq(struct irq_data *d)
{
}

static void extioi_mask_irq(struct irq_data *d)
{
}

static void extioi_unmask_irq(struct irq_data *d)
{
}
static struct irq_chip extioi_irq_chip = {
	.name			= "EIOINTC",
	.irq_ack		= extioi_ack_irq,
	.irq_mask		= extioi_mask_irq,
	.irq_unmask		= extioi_unmask_irq,
	.irq_set_affinity	= ext_set_irq_affinity,
};

static int extioi_domain_translate(struct irq_domain *d,
					struct irq_fwspec *fwspec,
					unsigned long *hwirq,
					unsigned int *type)
{
	if (fwspec->param_count < 1)
		return -EINVAL;
	*hwirq = fwspec->param[0];
	*type = IRQ_TYPE_NONE;
	return 0;
}

static int extioi_domain_alloc(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs, void *arg)
{
	unsigned int type, i;
	unsigned long hwirq = 0;
	struct extioi *priv = domain->host_data;

	extioi_domain_translate(domain, arg, &hwirq, &type);

	if (hwirq >= IOCSR_EXTIOI_VECTOR_NUM)
		return -EINVAL;

	for (i = 0; i < nr_irqs; i++) {
		irq_domain_set_info(domain, virq + i, hwirq + i, &extioi_irq_chip,
					priv, handle_edge_irq, NULL, NULL);
	}

	return 0;
}

static void extioi_domain_free(struct irq_domain *domain, unsigned int virq,
				unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);

		irq_set_handler(virq + i, NULL);
		irq_domain_reset_irq_data(d);
	}
}

static const struct irq_domain_ops extioi_domain_ops = {
	.translate	= extioi_domain_translate,
	.alloc		= extioi_domain_alloc,
	.free		= extioi_domain_free,
};

int extioi_vec_init(struct fwnode_handle *fwnode, int cascade,
		u32 vec_count,
		u32 misc_func,
		u32 eio_en_off,
		u64 node_map,
		u32 node)
{
	int err, i;

	extioi_priv[nr_extioi] = kzalloc(sizeof(struct extioi), GFP_KERNEL);
	if (!extioi_priv[nr_extioi])
		return -ENOMEM;

	extioi_priv[nr_extioi]->extioi_domain = irq_domain_create_linear(fwnode, vec_count,
					&extioi_domain_ops, extioi_priv[nr_extioi]);
	if (!extioi_priv[nr_extioi]->extioi_domain) {
		pr_err("loongson-extioi: cannot add IRQ domain\n");
		err = -ENOMEM;
		goto failed_exit;
	}
	extioi_priv[nr_extioi]->misc_func = misc_func;
	extioi_priv[nr_extioi]->eio_en_off = eio_en_off;
	extioi_priv[nr_extioi]->vec_count = vec_count;

	node_map = node_map ? node_map : -1ULL;
	for_each_possible_cpu(i) {
		if (node_map & (1ULL << (cpu_to_eio_node(i)))) {
			node_set(cpu_to_eio_node(i), extioi_priv[nr_extioi]->node_map);
			cpumask_or(&extioi_priv[nr_extioi]->cpuspan_map,
				&extioi_priv[nr_extioi]->cpuspan_map, cpumask_of(i));
		}
	}
	extioi_priv[nr_extioi]->node = node;

	irq_set_chained_handler_and_data(cascade,
					extioi_irq_dispatch,
					extioi_priv[nr_extioi]);
	extioi_priv[nr_extioi]->domain_handle = fwnode;

	if (get_irq_route_model() == PCH_IRQ_ROUTE_EXT_SOC)
		irq_set_default_host(extioi_priv[nr_extioi]->extioi_domain);

	nr_extioi++;
	extioi_init();
	return 0;

failed_exit:
	kfree(extioi_priv[nr_extioi]);

	return err;
}

static int __init eiointc_of_init(struct device_node *of_node,
				struct device_node *parent)
{
	u32 cascade, vec_count, misc_func, eio_en_off;

	cascade = of_irq_get_byname(of_node, "cascade");
	of_property_read_u32(of_node, "vec_count", &vec_count);
	of_property_read_u32(of_node, "misc_func", &misc_func);
	of_property_read_u32(of_node, "eio_en_off", &eio_en_off);
	extioi_vec_init(of_node_to_fwnode(of_node), cascade,
			vec_count,
			misc_func,
			eio_en_off,
			0, 0);
	return 0;
}
IRQCHIP_DECLARE(extioi_intc, "loongson,extioi-interrupt-controller", eiointc_of_init);

#ifdef CONFIG_PM
static bool extioi_managed_irq(struct irq_data *irq_data)
{
	int i;
	struct irq_domain *parent;

	for (parent = irq_data->domain; parent; parent = parent->parent) {
		for (i = 0; i < nr_extioi; i++) {
			if (extioi_priv[i]->extioi_domain == parent)
				return true;
		}
	}

	return false;
}

static void extioi_irq_resume(void)
{
	int i;
	struct irq_desc *desc;
	struct irq_data *irq_data;
	extioi_init();

	for (i = 0; i < NR_IRQS; i++) {
		desc = irq_to_desc(i);
		if (desc && desc->handle_irq != NULL &&
				desc->handle_irq != handle_bad_irq) {
			irq_data = &desc->irq_data;
			if (extioi_managed_irq(irq_data))
				ext_set_irq_affinity(&desc->irq_data, desc->irq_data.common->affinity, 0);
		}
	}
}

static int extioi_irq_suspend(void)
{
	return 0;
}

#else
#define extioi_irq_suspend NULL
#define extioi_irq_resume NULL
#endif

static struct syscore_ops extioi_irq_syscore_ops = {
	.suspend = extioi_irq_suspend,
	.resume = extioi_irq_resume,
};

static int __init extioi_init_syscore_ops(void)
{
	if (extioi_priv[0])
		register_syscore_ops(&extioi_irq_syscore_ops);
	return 0;
}
device_initcall(extioi_init_syscore_ops);

#if defined(CONFIG_ACPI)
static int __init eiointc_acpi_init_v1(struct acpi_subtable_header *header,
				   const unsigned long end)
{
	struct acpi_madt_eio_pic *eiointc_entry;
	struct irq_fwspec fwspec;
	struct fwnode_handle *fwnode;
	int parent_irq;
	eiointc_entry = (struct acpi_madt_eio_pic *)header;

	fwnode = irq_domain_alloc_named_id_fwnode("eiointc", nr_extioi);
	if (!fwnode) {
		pr_err("Unable to allocate domain handle\n");
		return -ENOMEM;
	}

	fwspec.fwnode = coreintc_get_fwnode();
	fwspec.param[0] = eiointc_entry->cascade;
	fwspec.param_count = 1;
	parent_irq = irq_create_fwspec_mapping(&fwspec);
	if (parent_irq > 0)
		extioi_vec_init(fwnode, parent_irq, IOCSR_EXTIOI_VECTOR_NUM, 0, 0, eiointc_entry->node_map, eiointc_entry->node);
	return 0;
}
IRQCHIP_ACPI_DECLARE(eiointc_v1, ACPI_MADT_TYPE_EIO_PIC,
		NULL, ACPI_MADT_EIO_PIC_VERSION_V1,
		eiointc_acpi_init_v1);
#endif
