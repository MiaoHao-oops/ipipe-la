/*
 * CPUFreq driver for the loongson-2k processors
 *
 * All revisions of Loongson-2k processor support this feature.
 *
 * Copyright (C) 2021 Loongson Inc.
 * Author: Ming Wang, wangming01@loongson.com
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <linux/module.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/cpufreq.h>
#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <asm/idle.h>
#include <asm/clock.h>
#include <asm/cevt-r4k.h>
#include <linux/clk.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

#include <loongson.h>
#include <loongson-2k.h>

extern u32 node_pll_l2_out;

/* Minimum CLK support */
enum {
	DC_ZERO, DC_6PT = 6, DC_5PT = 5, DC_4PT = 4, DC_3PT = 3,
	DC_DISABLE = 2, DC_RESV
};

static struct cpufreq_frequency_table loongson2k_clockmod_table[] = {
	{0, DC_ZERO, CPUFREQ_ENTRY_INVALID},
	{0, DC_6PT, 0},
	{0, DC_5PT, 0},
	{0, DC_4PT, 0},
	{0, DC_3PT, 0},
	{0, DC_DISABLE, 0},
	{0, DC_RESV, CPUFREQ_TABLE_END},
};

struct loongson2k_volt {
	unsigned int	vid;
	unsigned int	freq;
};

static bool regulator_enabled __maybe_unused;
static struct loongson2k_volt *voltage_tbale;
static struct device *cpu_dev;
static struct mutex cpufreq_reg_mutex[MAX_PACKAGES];
static int loongson2k_cpu_freq_notifier(struct notifier_block *nb,
					unsigned long val, void *data);
static struct notifier_block loongson2k_cpufreq_notifier_block = {
	.notifier_call = loongson2k_cpu_freq_notifier
};

#ifdef CONFIG_SMP
static int loongson2k_cpu_freq_notifier(struct notifier_block *nb,
					unsigned long val, void *data)
{
	struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)data;
	unsigned long cpu = freqs->cpu;
	struct clock_event_device *cd;

	cd = &per_cpu(mips_clockevent_device, cpu);

	if (val == CPUFREQ_POSTCHANGE) {
		if (cpu == smp_processor_id())
			clockevents_update_freq(cd, freqs->new * 1000 / 2);
		else {
			clockevents_calc_mult_shift(cd, freqs->new * 1000 / 2, 4);
			cd->min_delta_ns = clockevent_delta2ns(cd->min_delta_ticks, cd);
			cd->max_delta_ns = clockevent_delta2ns(cd->max_delta_ticks, cd);
		}
		cpu_data[cpu].udelay_val = loops_per_jiffy;
	}

	return 0;
}
#else
static int loongson2k_cpu_freq_notifier(struct notifier_block *nb,
					unsigned long val, void *data)
{
	struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)data;
	struct clock_event_device *cd = &per_cpu(mips_clockevent_device, 0);

	if (val == CPUFREQ_POSTCHANGE) {
		clockevents_update_freq(cd, freqs->new * 1000 / 2);
		current_cpu_data.udelay_val = loops_per_jiffy;
	}

	return 0;
}
#endif

static unsigned int loongson2k_cpufreq_get(unsigned int cpu)
{
	unsigned int reg;
	unsigned int div;
	unsigned int freq;

	reg = acpi_readl(DVFS_STS);

	div = (reg & DVFS_STS_FEQ_STS_MASK) >> DVFS_STS_FEQ_STS_OFFSET;

	if (div)
		freq = (cpu_clock_freq * node_pll_l2_out / div / 1000);
	else
		freq = (cpu_clock_freq / 1000);

	return freq;
}

/*
 * Here we notify other drivers of the proposed change and the final change.
 */
static int loongson2k_cpufreq_target(struct cpufreq_policy *policy,
				     unsigned int index)
{
	int ret = 0, i = 0;
	unsigned int cpu = policy->cpu;
	unsigned int package = cpu_data[cpu].package;
	unsigned int old_freq, new_freq;
	struct cpufreq_frequency_table *pos;

	old_freq = policy->cur;
	new_freq = loongson2k_clockmod_table[index].frequency;

	if (!cpu_online(cpu))
		return -ENODEV;

#ifdef CONFIG_REGULATOR
	if (regulator_enabled) {
		for (i = 0; voltage_tbale[i].freq != new_freq; i++)
			;

		/* TODO: Add voltage latency support */
		if (new_freq > old_freq) {
			acpi_writel(DVFS_CNT_POL_UP | DVFS_CNT_VID(voltage_tbale[i].vid), DVFS_CNT);
		} else {
			acpi_writel(DVFS_CNT_POL_DOWN & DVFS_CNT_VID(voltage_tbale[i].vid), DVFS_CNT);
		}
	}
#endif

	cpufreq_for_each_valid_entry(pos, loongson2k_clockmod_table)
		if (new_freq == pos->frequency)
			break;
	if (new_freq != pos->frequency)
		return -ENOTSUPP;

	mutex_lock(&cpufreq_reg_mutex[package]);

	/* Set NODE PLL L1_DIV_OUT parameter and enable UPDATE */
	acpi_writel(acpi_readl(DVFS_CNT) | DVFS_CNT_DIV(pos->driver_data) | DVFS_CNT_UPDATE_EN, DVFS_CNT);

	/* Start DVFS convert */
	acpi_writel(acpi_readl(DVFS_CNT) | DVFS_CNT_START, DVFS_CNT);

	/* Wait for the conversion to complete */
	while ((acpi_readl(DVFS_STS) & DVFS_STS_STATUS_MASK))
		;

	mutex_unlock(&cpufreq_reg_mutex[package]);

	pr_debug("DVFS_CNT:%#x DVFS_STS: %#x DVFS_CFG: %#x \n",
			acpi_readl(DVFS_CNT), acpi_readl(DVFS_STS), acpi_readl(DVFS_CFG));

	return ret;
}

static int loongson2k_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	if (!cpu_online(policy->cpu))
		return -ENODEV;

	policy->cur = loongson2k_cpufreq_get(policy->cpu);

	policy->cpuinfo.transition_latency = 1000;
	policy->freq_table = loongson2k_clockmod_table;

	/* Loongson-2k: all cores in a package share one clock */
	cpumask_copy(policy->cpus, topology_core_cpumask(policy->cpu));

	return 0;
}

static int loongson2k_cpufreq_exit(struct cpufreq_policy *policy)
{
	return 0;
}

static struct cpufreq_driver loongson2k_cpufreq_driver = {
	.name = "ls2k-cpufreq",
	.init = loongson2k_cpufreq_cpu_init,
	.verify = cpufreq_generic_frequency_table_verify,
	.target_index = loongson2k_cpufreq_target,
	.get = loongson2k_cpufreq_get,
	.exit = loongson2k_cpufreq_exit,
	.attr = cpufreq_generic_attr,
	.suspend = cpufreq_generic_suspend,
};

static int loongson2k_cpufreq_probe(struct platform_device *pdev)
{
	struct device_node *np __maybe_unused;
	const struct property *prop __maybe_unused;
	const __be32 *val __maybe_unused;
	u32 nr, i __maybe_unused;
	int ret;

#ifdef CONFIG_REGULATOR
	regulator_enabled = true;

	cpu_dev = get_cpu_device(0);
	if (!cpu_dev) {
		pr_err("failed to get cpu0 device\n");
		regulator_enabled = false;
		goto freq_out;
	}

	np = of_node_get(cpu_dev->of_node);
	if (!np) {
		dev_err(cpu_dev, "failed to find cpu0 node\n");
		regulator_enabled = false;
		goto freq_out;
	}

	prop = of_find_property(np, "loongson,dvfs-vid-points", NULL);
	if (!prop || !prop->value) {
		pr_err("failed to of_find_property loongson,dvfs\n");
		regulator_enabled = false;
		goto freq_out;
	}

	nr = prop->length / sizeof(u32);
	if (!(nr % 2)) {
		voltage_tbale = devm_kcalloc(cpu_dev, (nr + 1),
							sizeof(struct loongson2k_volt), GFP_KERNEL);
		val = prop->value;
		for (i = 0; i < nr / 2; i++) {
			voltage_tbale[i].freq = be32_to_cpup(val++);
			voltage_tbale[i].vid = be32_to_cpup(val++);
		}
		voltage_tbale[nr].vid = 0;
		voltage_tbale[nr].freq = CPUFREQ_TABLE_END;
	} else {
		regulator_enabled = false;
	}
#endif

freq_out:
	/* clock table init */
	for (i = MIN_FREQ_LEVEL; (loongson2k_clockmod_table[i].frequency != CPUFREQ_TABLE_END); i++)
		loongson2k_clockmod_table[i].frequency =
			(cpu_clock_freq * node_pll_l2_out / loongson2k_clockmod_table[i].driver_data / 1000);

	/* Enable loongson2k DVFS and use the backup clock for protection */
	acpi_writel(DVFS_CFG_DVFS_EN | DVFS_CFG_BACKUP_CLOCK | DVFS_CFG_PROTECT_FULL, DVFS_CFG);

	for (i = 0; i < MAX_PACKAGES; i++)
		mutex_init(&cpufreq_reg_mutex[i]);

	cpufreq_register_notifier(&loongson2k_cpufreq_notifier_block,
		  CPUFREQ_TRANSITION_NOTIFIER);

	ret = cpufreq_register_driver(&loongson2k_cpufreq_driver);

	pr_info("cpufreq: Loongson-2k CPU frequency driver.\n");

	return ret;
}

static int loongson2k_cpufreq_remove(struct platform_device *pdev)
{
	cpufreq_unregister_driver(&loongson2k_cpufreq_driver);
	devm_kfree(cpu_dev, voltage_tbale);
	voltage_tbale = NULL;

	return 0;
}

static struct platform_device_id platform_device_ids[] = {
	{
		.name = "loongson2k_cpufreq",
	},
	{}
};
MODULE_DEVICE_TABLE(platform, platform_device_ids);

static struct platform_driver loongson2k_cpufreq_platdrv = {
	.driver = {
		.name = "loongson2k_cpufreq",
		.owner = THIS_MODULE,
	},
	.id_table = platform_device_ids,
	.probe = loongson2k_cpufreq_probe,
	.remove = loongson2k_cpufreq_remove,
};
module_platform_driver(loongson2k_cpufreq_platdrv);

MODULE_AUTHOR("Ming Wang <wangming01@loongson.cn>");
MODULE_DESCRIPTION("CPUFreq driver for Loongson-2k");
MODULE_LICENSE("GPL");
