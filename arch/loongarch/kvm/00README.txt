KVM/LOONGISA VZ Release Notes
=====================================

(1) KVM/LOONGISA should support LOONGISA V1 and beyond.

(2) 16K basic Page Sizes: Both Host Kernel and Guest Kernel should have the same page size, currently at least 16K.
    Note that due to cache aliasing issues, 4K page sizes are NOT supported.

(3) HugeTLB Support

(4) KVM/LOONGISA does have support for SMP Guests

(5) Use Host FPU
