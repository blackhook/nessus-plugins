#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2308.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129807);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/24");

  script_cve_id("CVE-2017-18595", "CVE-2019-14821", "CVE-2019-15291", "CVE-2019-9506");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2019-2308)");
  script_summary(english:"Check for the openSUSE-2019-2308 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2019-15291: There was a NULL pointer dereference
    caused by a malicious USB device in the
    flexcop_usb_probe function in the
    drivers/media/usb/b2c2/flexcop-usb.c driver
    (bnc#1146540).

  - CVE-2019-14821: An out-of-bounds access issue was found
    in the way Linux kernel's KVM hypervisor implements the
    Coalesced MMIO write operation. It operates on an MMIO
    ring buffer 'struct kvm_coalesced_mmio' object, wherein
    write indices 'ring->first' and 'ring->last' value could
    be supplied by a host user-space process. An
    unprivileged host user or process with access to
    '/dev/kvm' device could use this flaw to crash the host
    kernel, resulting in a denial of service or potentially
    escalating privileges on the system (bnc#1151350).

  - CVE-2017-18595: A double free may be caused by the
    function allocate_trace_buffer in the file
    kernel/trace/trace.c (bnc#1149555).

  - CVE-2019-9506: The Bluetooth BR/EDR specification up to
    and including version 5.1 permits sufficiently low
    encryption key length and did not prevent an attacker
    from influencing the key length negotiation. This
    allowed practical brute-force attacks (aka 'KNOB') that
    can decrypt traffic and inject arbitrary ciphertext
    without the victim noticing (bnc#1137865 bnc#1146042).

The following non-security bugs were fixed :

  - ACPI: custom_method: fix memory leaks (bsc#1051510).

  - ACPI / PCI: fix acpi_pci_irq_enable() memory leak
    (bsc#1051510).

  - ACPI / property: Fix acpi_graph_get_remote_endpoint()
    name in kerneldoc (bsc#1051510).

  - alarmtimer: Use EOPNOTSUPP instead of ENOTSUPP
    (bsc#1151680).

  - ALSA: aoa: onyx: always initialize register read value
    (bsc#1051510).

  - ALSA: firewire-tascam: check intermediate state of clock
    status and retry (bsc#1051510).

  - ALSA: firewire-tascam: handle error code when getting
    current source of clock (bsc#1051510).

  - ASoC: es8328: Fix copy-paste error in
    es8328_right_line_controls (bsc#1051510).

  - ASoC: Intel: Baytrail: Fix implicit fallthrough warning
    (bsc#1051510).

  - ASoC: sun4i-i2s: RX and TX counter registers are swapped
    (bsc#1051510).

  - ASoC: wm8737: Fix copy-paste error in
    wm8737_snd_controls (bsc#1051510).

  - ASoC: wm8988: fix typo in wm8988_right_line_controls
    (bsc#1051510).

  - ath10k: adjust skb length in ath10k_sdio_mbox_rx_packet
    (bsc#1111666).

  - ath9k: dynack: fix possible deadlock in
    ath_dynack_node_(de)init (bsc#1051510).

  - atm: iphase: Fix Spectre v1 vulnerability
    (networking-stable-19_08_08).

  - bcma: fix incorrect update of BCMA_CORE_PCI_MDIO_DATA
    (bsc#1051510).

  - blk-flush: do not run queue for requests bypassing flush
    (bsc#1137959).

  - blk-flush: use blk_mq_request_bypass_insert()
    (bsc#1137959).

  - blk-mq: do not allocate driver tag upfront for flush rq
    (bsc#1137959).

  - blk-mq: Fix memory leak in blk_mq_init_allocated_queue
    error handling (bsc#1151610).

  - blk-mq: insert rq with DONTPREP to hctx dispatch list
    when requeue (bsc#1137959).

  - blk-mq: introduce blk_mq_request_completed()
    (bsc#1149446).

  - blk-mq: introduce blk_mq_tagset_wait_completed_request()
    (bsc#1149446).

  - blk-mq: kABI fixes for blk-mq.h (bsc#1137959).

  - blk-mq: move blk_mq_put_driver_tag*() into blk-mq.h
    (bsc#1137959).

  - blk-mq: punt failed direct issue to dispatch list
    (bsc#1137959).

  - blk-mq: put the driver tag of nxt rq before first one is
    requeued (bsc#1137959).

  - blk-mq-sched: decide how to handle flush rq via
    RQF_FLUSH_SEQ (bsc#1137959).

  - block: fix timeout changes for legacy request drivers
    (bsc#1149446).

  - block: kABI fixes for BLK_EH_DONE renaming
    (bsc#1142076).

  - block: rename BLK_EH_NOT_HANDLED to BLK_EH_DONE
    (bsc#1142076).

  - bnx2x: Disable multi-cos feature
    (networking-stable-19_08_08).

  - bonding/802.3ad: fix link_failure_count tracking
    (bsc#1137069 bsc#1141013).

  - bonding/802.3ad: fix slave link initialization
    transition states (bsc#1137069 bsc#1141013).

  - bonding: Add vlan tx offload to hw_enc_features
    (networking-stable-19_08_21).

  - bonding: set default miimon value for non-arp modes if
    not set (bsc#1137069 bsc#1141013).

  - bonding: speed/duplex update at NETDEV_UP event
    (bsc#1137069 bsc#1141013).

  - btrfs: fix use-after-free when using the tree
    modification log (bsc#1151891).

  - btrfs: qgroup: Fix reserved data space leak if we have
    multiple reserve calls (bsc#1152975).

  - btrfs: qgroup: Fix the wrong target io_tree when freeing
    reserved data space (bsc#1152974).

  - btrfs: relocation: fix use-after-free on dead relocation
    roots (bsc#1152972).

  - ceph: use ceph_evict_inode to cleanup inode's resource
    (bsc#1148133).

  - clk: at91: fix update bit maps on CFG_MOR write
    (bsc#1051510).

  - clk: sunxi-ng: v3s: add missing clock slices for MMC2
    module clocks (bsc#1051510).

  - clk: sunxi-ng: v3s: add the missing PLL_DDR1
    (bsc#1051510).

  - Compile nvme.ko as module (bsc#1150846)

  - crypto: caam - fix concurrency issue in givencrypt
    descriptor (bsc#1051510).

  - crypto: caam - free resources in case caam_rng
    registration failed (bsc#1051510).

  - crypto: caam/qi - fix error handling in ERN handler
    (bsc#1111666).

  - crypto: cavium/zip - Add missing single_release()
    (bsc#1051510).

  - crypto: ccp - Reduce maximum stack usage (bsc#1051510).

  - crypto: qat - Silence smp_processor_id() warning
    (bsc#1051510).

  - crypto: skcipher - Unmap pages after an external error
    (bsc#1051510).

  - dma-buf/sw_sync: Synchronize signal vs syncpt free
    (bsc#1111666).

  - dmaengine: dw: platform: Switch to
    acpi_dma_controller_register() (bsc#1051510).

  - dmaengine: iop-adma.c: fix printk format warning
    (bsc#1051510).

  - drivers: thermal: int340x_thermal: Fix sysfs race
    condition (bsc#1051510).

  - drm/i915: Fix various tracepoints for gen2 (bsc#1113722)

  - drm/imx: Drop unused imx-ipuv3-crtc.o build
    (bsc#1113722)

  - EDAC/amd64: Decode syndrome before translating address
    (bsc#1114279).

  - eeprom: at24: make spd world-readable again (git-fixes).

  - ext4: fix warning inside
    ext4_convert_unwritten_extents_endio (bsc#1152025).

  - ext4: set error return correctly when
    ext4_htree_store_dirent fails (bsc#1152024).

  - Fix kabi for: NFSv4: Fix OPEN / CLOSE race (git-fixes).

  - floppy: fix usercopy direction (bsc#1111666).

  - git-sort: add nfsd maintainers git tree This allows
    git-sort to handle patches queued for nfsd.

  - gpio: fix line flag validation in lineevent_create
    (bsc#1051510).

  - gpio: fix line flag validation in linehandle_create
    (bsc#1051510).

  - gpiolib: acpi: Add gpiolib_acpi_run_edge_events_on_boot
    option and blacklist (bsc#1051510).

  - gpiolib: only check line handle flags once
    (bsc#1051510).

  - gpio: Move gpiochip_lock/unlock_as_irq to gpio/driver.h
    (bsc#1051510).

  - hwmon: (lm75) Fix write operations for negative
    temperatures (bsc#1051510).

  - hwmon: (shtc1) fix shtc1 and shtw1 id mask
    (bsc#1051510).

  - i2c: designware: Synchronize IRQs when unregistering
    slave client (bsc#1111666).

  - i40e: Add support for X710 device (bsc#1151067).

  - ife: error out when nla attributes are empty
    (networking-stable-19_08_08).

  - iio: dac: ad5380: fix incorrect assignment to val
    (bsc#1051510).

  - Input: elan_i2c - remove Lenovo Legion Y7000 PnpID
    (bsc#1051510).

  - iommu/dma: Fix for dereferencing before null checking
    (bsc#1151667).

  - iommu: Do not use sme_active() in generic code
    (bsc#1151661).

  - iommu/iova: Avoid false sharing on fq_timer_on
    (bsc#1151662).

  - ip6_tunnel: fix possible use-after-free on xmit
    (networking-stable-19_08_08).

  - ipv6/addrconf: allow adding multicast addr if
    IFA_F_MCAUTOJOIN is set (networking-stable-19_08_28).

  - isdn/capi: check message length in capi_write()
    (bsc#1051510).

  - kABI: media: em28xx: fix handler for vidioc_s_input()
    (bsc#1051510). fixes kABI

  - kABI: media: em28xx: stop rewriting device's struct
    (bsc#1051510). fixes kABI

  - kABI protect struct vmem_altmap (bsc#1150305).

  - KVM: PPC: Book3S: Fix incorrect
    guest-to-user-translation error handling (bsc#1061840).

  - KVM: PPC: Book3S HV: Check for MMU ready on piggybacked
    virtual cores (bsc#1061840).

  - KVM: PPC: Book3S HV: Do not lose pending doorbell
    request on migration on P9 (bsc#1061840).

  - KVM: PPC: Book3S HV: Do not push XIVE context when not
    using XIVE device (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix lockdep warning when entering
    the guest (bsc#1061840).

  - KVM: PPC: Book3S HV: Fix race in re-enabling XIVE
    escalation interrupts (bsc#1061840).

  - KVM: PPC: Book3S HV: Handle virtual mode in XIVE VCPU
    push code (bsc#1061840).

  - KVM: PPC: Book3S HV: XIVE: Free escalation interrupts
    before disabling the VP (bsc#1061840).

  - leds: leds-lp5562 allow firmware files up to the maximum
    length (bsc#1051510).

  - leds: trigger: gpio: GPIO 0 is valid (bsc#1051510).

  - libertas_tf: Use correct channel range in lbtf_geo_init
    (bsc#1051510).

  - libiscsi: do not try to bypass SCSI EH (bsc#1142076).

  - libnvdimm/altmap: Track namespace boundaries in altmap
    (bsc#1150305).

  - libnvdimm: prevent nvdimm from requesting key when
    security is disabled (bsc#1137982).

  - lightnvm: remove dependencies on BLK_DEV_NVME and PCI
    (bsc#1150846).

  - livepatch: Nullify obj->mod in klp_module_coming()'s
    error path (bsc#1071995).

  - mac80211: minstrel_ht: fix per-group max throughput rate
    initialization (bsc#1051510).

  - md: do not report active array_state until after
    revalidate_disk() completes (git-fixes).

  - md: only call set_in_sync() when it is expected to
    succeed (git-fixes).

  - md/raid6: Set R5_ReadError when there is read failure on
    parity disk (git-fixes).

  - media: atmel: atmel-isi: fix timeout value for stop
    streaming (bsc#1051510).

  - media: dib0700: fix link error for dibx000_i2c_set_speed
    (bsc#1051510).

  - media: em28xx: fix handler for vidioc_s_input()
    (bsc#1051510).

  - media: em28xx: stop rewriting device's struct
    (bsc#1051510).

  - media: fdp1: Reduce FCP not found message level to debug
    (bsc#1051510).

  - media: marvell-ccic: do not generate EOF on parallel bus
    (bsc#1051510).

  - media: mc-device.c: do not memset __user pointer
    contents (bsc#1051510).

  - media: ov6650: Fix sensor possibly not detected on probe
    (bsc#1051510).

  - media: ov6650: Move v4l2_clk_get() to
    ov6650_video_probe() helper (bsc#1051510).

  - media: replace strcpy() by strscpy() (bsc#1051510).

  - media: Revert '[media] marvell-ccic: reset ccic phy when
    stop streaming for stability' (bsc#1051510).

  - media: technisat-usb2: break out of loop at end of
    buffer (bsc#1051510).

  - media: tm6000: double free if usb disconnect while
    streaming (bsc#1051510).

  - media: vb2: Fix videobuf2 to map correct area
    (bsc#1051510).

  - mic: avoid statically declaring a 'struct device'
    (bsc#1051510).

  - mmc: sdhci-msm: fix mutex while in spinlock
    (bsc#1142635).

  - mmc: sdhci-of-arasan: Do now show error message in case
    of deffered probe (bsc#1119086).

  - mtd: spi-nor: Fix Cadence QSPI RCU Schedule Stall
    (bsc#1051510).

  - mvpp2: refactor MTU change code
    (networking-stable-19_08_08).

  - net: bridge: delete local fdb on device init failure
    (networking-stable-19_08_08).

  - net: bridge: mcast: do not delete permanent entries when
    fast leave is enabled (networking-stable-19_08_08).

  - net: fix ifindex collision during namespace removal
    (networking-stable-19_08_08).

  - net/ibmvnic: prevent more than one thread from running
    in reset (bsc#1152457 ltc#174432).

  - net/ibmvnic: unlock rtnl_lock in reset so
    linkwatch_event can run (bsc#1152457 ltc#174432).

  - net/mlx5e: Only support tx/rx pause setting for port
    owner (networking-stable-19_08_21).

  - net/mlx5e: Prevent encap flow counter update async to
    user query (networking-stable-19_08_08).

  - net/mlx5e: Use flow keys dissector to parse packets for
    ARFS (networking-stable-19_08_21).

  - net/mlx5: Use reversed order when unregister devices
    (networking-stable-19_08_08).

  - net/packet: fix race in tpacket_snd()
    (networking-stable-19_08_21).

  - net: sched: Fix a possible NULL pointer dereference in
    dequeue_func() (networking-stable-19_08_08).

  - net/smc: make sure EPOLLOUT is raised
    (networking-stable-19_08_28).

  - NFS4: Fix v4.0 client state corruption when mount
    (git-fixes).

  - nfsd: degraded slot-count more gracefully as allocation
    nears exhaustion (bsc#1150381).

  - nfsd: Do not release the callback slot unless it was
    actually held (git-fixes).

  - nfsd: Fix overflow causing non-working mounts on 1 TB
    machines (bsc#1150381).

  - nfsd: fix performance-limiting session calculation
    (bsc#1150381).

  - nfsd: give out fewer session slots as limit approaches
    (bsc#1150381).

  - nfsd: handle drc over-allocation gracefully
    (bsc#1150381).

  - nfsd: increase DRC cache limit (bsc#1150381).

  - NFS: Do not interrupt file writeout due to fatal errors
    (git-fixes).

  - NFS: Do not open code clearing of delegation state
    (git-fixes).

  - NFS: Ensure O_DIRECT reports an error if the bytes
    read/written is 0 (git-fixes).

  - NFS: Fix regression whereby fscache errors are appearing
    on 'nofsc' mounts (git-fixes).

  - NFS: Forbid setting AF_INET6 to 'struct
    sockaddr_in'->sin_family (git-fixes).

  - NFS: Refactor nfs_lookup_revalidate() (git-fixes).

  - NFS: Remove redundant semicolon (git-fixes).

  - NFSv4.1: Again fix a race where CB_NOTIFY_LOCK fails to
    wake a waiter (git-fixes).

  - NFSv4.1: Fix open stateid recovery (git-fixes).

  - NFSv4.1: Only reap expired delegations (git-fixes).

  - NFSv4: Check the return value of update_open_stateid()
    (git-fixes).

  - NFSv4: Fix an Oops in nfs4_do_setattr (git-fixes).

  - NFSv4: Fix a potential sleep while atomic in
    nfs4_do_reclaim() (git-fixes).

  - NFSv4: Fix delegation state recovery (git-fixes).

  - NFSv4: Fix lookup revalidate of regular files
    (git-fixes).

  - NFSv4: Fix OPEN / CLOSE race (git-fixes).

  - NFSv4: Handle the special Linux file open access mode
    (git-fixes).

  - NFSv4: Only pass the delegation to setattr if we're
    sending a truncate (git-fixes).

  - NFSv4/pnfs: Fix a page lock leak in nfs_pageio_resend()
    (git-fixes).

  - nl80211: Fix possible Spectre-v1 for CQM RSSI thresholds
    (bsc#1051510).

  - null_blk: complete requests from ->timeout
    (bsc#1149446).

  - null_blk: wire up timeouts (bsc#1149446).

  - nvme: do not abort completed request in
    nvme_cancel_request (bsc#1149446).

  - nvme: fix multipath crash when ANA is deactivated
    (bsc#1149446).

  - nvme: fix multipath crash when ANA is deactivated
    (bsc#1149446).

  - nvmem: Use the same permissions for eeprom as for nvmem
    (git-fixes).

  - nvme-rdma: Allow DELETING state change failure in
    (bsc#1104967,).

  - nvme-rdma: centralize admin/io queue teardown sequence
    (bsc#1142076).

  - nvme-rdma: centralize controller setup sequence
    (bsc#1142076).

  - nvme-rdma: fix a NULL deref when an admin connect times
    out (bsc#1149446).

  - nvme-rdma: fix a NULL deref when an admin connect times
    out (bsc#1149446).

  - nvme-rdma: fix timeout handler (bsc#1149446).

  - nvme-rdma: fix timeout handler (bsc#1149446).

  - nvme-rdma: remove redundant reference between ib_device
    and tagset (bsc#149446).

  - nvme-rdma: stop admin queue before freeing it
    (bsc#1140155).

  - nvme-rdma: support up to 4 segments of inline data
    (bsc#1142076).

  - nvme-rdma: unquiesce queues when deleting the controller
    (bsc#1142076).

  - nvme-rdma: use dynamic dma mapping per command
    (bsc#1149446).

  - nvme: remove ns sibling before clearing path
    (bsc#1140155).

  - nvme: return BLK_EH_DONE from ->timeout (bsc#1142076).

  - nvme-tcp: fix a NULL deref when an admin connect times
    out (bsc#1149446).

  - nvme-tcp: fix timeout handler (bsc#1149446).

  - nvme: wait until all completed request's complete fn is
    called (bsc#1149446).

  - PCI: Add ACS quirk for Amazon Annapurna Labs root ports
    (bsc#1152187,bsc#1152525).

  - PCI: Add Amazon's Annapurna Labs vendor ID
    (bsc#1152187,bsc#1152525).

  - PCI: Add quirk to disable MSI-X support for Amazon's
    Annapurna Labs Root Port (bsc#1152187,bsc#1152525).

  - PCI: hv: Detect and fix Hyper-V PCI domain number
    collision (bsc#1150423).

  - PCI/VPD: Prevent VPD access for Amazon's Annapurna Labs
    Root Port (bsc#1152187,bsc#1152525).

  - phy: renesas: rcar-gen3-usb2: Disable clearing VBUS in
    over-current (bsc#1051510).

  - platform/x86: pmc_atom: Add Siemens SIMATIC IPC227E to
    critclk_systems DMI table (bsc#1051510).

  - PM: sleep: Fix possible overflow in
    pm_system_cancel_wakeup() (bsc#1051510).

  - PNFS fallback to MDS if no deviceid found (git-fixes).

  - pnfs/flexfiles: Fix PTR_ERR() dereferences in
    ff_layout_track_ds_error (git-fixes).

  - pNFS/flexfiles: Turn off soft RPC calls (git-fixes).

  - powerpc/64: Make sys_switch_endian() traceable
    (bsc#1065729).

  - powerpc/64s/radix: Fix MADV_[FREE|DONTNEED] TLB flush
    miss problem with THP (bsc#1152161 ltc#181664).

  - powerpc/64s/radix: Fix memory hotplug section page table
    creation (bsc#1065729).

  - powerpc/64s/radix: Fix memory hot-unplug page table
    split (bsc#1065729).

  - powerpc/64s/radix: Implement _tlbie(l)_va_range flush
    functions (bsc#1152161 ltc#181664).

  - powerpc/64s/radix: Improve preempt handling in TLB code
    (bsc#1152161 ltc#181664).

  - powerpc/64s/radix: Improve TLB flushing for page table
    freeing (bsc#1152161 ltc#181664).

  - powerpc/64s/radix: Introduce local single page ceiling
    for TLB range flush (bsc#1055117 bsc#1152161
    ltc#181664).

  - powerpc/64s/radix: Optimize flush_tlb_range (bsc#1152161
    ltc#181664).

  - powerpc/book3s64/mm: Do not do tlbie fixup for some
    hardware revisions (bsc#1152161 ltc#181664).

  - powerpc/book3s64/radix: Rename CPU_FTR_P9_TLBIE_BUG
    feature flag (bsc#1152161 ltc#181664).

  - powerpc: bpf: Fix generation of load/store DW
    instructions (bsc#1065729).

  - powerpc/bpf: use unsigned division instruction for
    64-bit operations (bsc#1065729).

  - powerpc: Drop page_is_ram() and walk_system_ram_range()
    (bsc#1065729).

  - powerpc/irq: Do not WARN continuously in
    arch_local_irq_restore() (bsc#1065729).

  - powerpc/irq: drop arch_early_irq_init() (bsc#1065729).

  - powerpc/mm: Fixup tlbie vs mtpidr/mtlpidr ordering issue
    on POWER9 (bsc#1152161 ltc#181664).

  - powerpc/mm/radix: Drop unneeded NULL check (bsc#1152161
    ltc#181664).

  - powerpc/mm/radix: implement LPID based TLB flushes to be
    used by KVM (bsc#1152161 ltc#181664).

  - powerpc/mm: Simplify page_is_ram by using
    memblock_is_memory (bsc#1065729).

  - powerpc/mm: Use memblock API for PPC32 page_is_ram
    (bsc#1065729).

  - powerpc/module64: Fix comment in R_PPC64_ENTRY handling
    (bsc#1065729).

  - powerpc/papr_scm: Fix an off-by-one check in
    papr_scm_meta_(get, set) (bsc#1152243 ltc#181472).

  - powerpc/powernv: Fix compile without CONFIG_TRACEPOINTS
    (bsc#1065729).

  - powerpc/powernv/ioda2: Allocate TCE table levels on
    demand for default DMA window (bsc#1061840).

  - powerpc/powernv/ioda: Fix race in TCE level allocation
    (bsc#1061840).

  - powerpc/powernv: move OPAL call wrapper tracing and
    interrupt handling to C (bsc#1065729).

  - powerpc/powernv/npu: Remove obsolete comment about
    TCE_KILL_INVAL_ALL (bsc#1065729).

  - powerpc/pseries: Call H_BLOCK_REMOVE when supported
    (bsc#1109158).

  - powerpc/pseries: Fix cpu_hotplug_lock acquisition in
    resize_hpt() (bsc#1065729).

  - powerpc/pseries/memory-hotplug: Fix return value type of
    find_aa_index (bsc#1065729).

  - powerpc/pseries: Read TLB Block Invalidate
    Characteristics (bsc#1109158).

  - powerpc/ptrace: Simplify vr_get/set() to avoid GCC
    warning (bsc#1148868).

  - powerpc/xive: Fix bogus error code returned by OPAL
    (bsc#1065729).

  - powerpc/xive: Implement get_irqchip_state method for
    XIVE to fix shutdown race (bsc#1065729).

  - powerpc/xmon: Fix opcode being uninitialized in
    print_insn_powerpc (bsc#1065729).

  - power: reset: gpio-restart: Fix typo when gpio reset is
    not found (bsc#1051510).

  - power: supply: Init device wakeup after device_add()
    (bsc#1051510).

  - ppp: Fix memory leak in ppp_write (git-fixes).

  - printk: Do not lose last line in kmsg buffer dump
    (bsc#1152460).

  - printk: fix printk_time race (bsc#1152466).

  - printk/panic: Avoid deadlock in printk() after stopping
    CPUs by NMI (bsc#1148712).

  - qla2xxx: kABI fixes for v10.01.00.18-k (bsc#1123034
    bsc#1131304 bsc#1127988).

  - qla2xxx: remove SGI SN2 support (bsc#1123034 bsc#1131304
    bsc#1127988).

  - quota: fix wrong condition in is_quota_modification()
    (bsc#1152026).

  - r8152: Set memory to all 0xFFs on failed reg reads
    (bsc#1051510).

  - Refresh
    scsi-qla2xxx-Capture-FW-dump-on-MPI-heartbeat-stop-e.pat
    ch 882ffc9f07fb ('scsi: qla2xxx: Capture FW dump on MPI
    heartbeat stop event (bsc#1123034 bsc#1131304
    bsc#1127988).') placed the 'vha->hw->fw_dump_mpi = 0'
    assigment into the __CHECKER__ section. Upstream placed
    the assigment before this section.

  - regulator: lm363x: Fix off-by-one n_voltages for lm3632
    ldo_vpos/ldo_vneg (bsc#1051510).

  - Remove
    patches.kabi/kABI-fixes-for-qla2xxx-Fix-inconsistent-DMA
    -mem-allo.patch The qla2xxx driver has been whitelisted
    by 1d5e8aad6de2 ('kabi/severities: ignore qla2xxx as all
    symbols are internal')

  - Revert 'mwifiex: fix system hang problem after resume'
    (bsc#1051510).

  - rtlwifi: Fix file release memory leak (bsc#1111666).

  - scsi: qla2xxx: Add 28xx flash primary/secondary
    status/image mechanism (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Add Device ID for ISP28XX (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add error handling for PLOGI ELS
    passthrough (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add First Burst support for FC-NVMe
    devices (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add fw_attr and port_no SysFS node
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add new FW dump template entry types
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add pci function reset support
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add protection mask module parameters
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add Serdes support for ISP28XX
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Add support for multiple fwdump
    templates/segments (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Add support for setting port speed
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Allow NVMe IO to resume with short cable
    pull (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: allow session delete to finish before
    create (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Always check the
    qla2x00_wait_for_hba_online() return value (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Avoid PCI IRQ affinity mapping when
    multiqueue is not supported (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: avoid printf format warning (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Avoid that Coverity complains about
    dereferencing a NULL rport pointer (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Avoid that lockdep complains about unsafe
    locking in tcm_qla2xxx_close_session() (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Avoid that qla2x00_mem_free() crashes if
    called twice (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Capture FW dump on MPI heartbeat stop
    event (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Change abort wait_loop from msleep to
    wait_event_timeout (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Change data_dsd into an array
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Change default ZIO threshold (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Change the return type of
    qla24xx_read_flash_data() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Change the return type of
    qla2x00_update_ms_fdmi_iocb() into void (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Check for FW started flag before aborting
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: check for kstrtol() failure (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Check for MB timeout while capturing
    ISP27/28xx FW dump (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Check secondary image if reading the
    primary image fails (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Check the PCI info string output buffer
    size (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Check the size of firmware data
    structures at compile time (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Cleanup fcport memory to prevent leak
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Cleanup redundant qla2x00_abort_all_cmds
    during unload (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Cleanups for NVRAM/Flash read/write path
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: cleanup trace buffer initialization
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Complain if a command is released that is
    owned by the firmware (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Complain if a mailbox command times out
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Complain if a soft reset fails
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Complain if parsing the version string
    fails (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Complain if sp->done() is not called from
    the completion path (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Complain if waiting for pending commands
    times out (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Complain loudly about reference count
    underflow (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Correct error handling during
    initialization failures (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Correction and improvement to fwdt
    processing (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Correctly report max/min supported speeds
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: deadlock by configfs_depend_item
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare fourth qla2x00_set_model_info()
    argument const (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare local symbols static (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare qla24xx_build_scsi_crc_2_iocbs()
    static (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare qla2x00_find_new_loop_id() static
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare qla_tgt_cmd.cdb const
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Declare the fourth ql_dump_buffer()
    argument const (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Disable T10-DIF feature with FC-NVMe
    during probe (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Do not corrupt vha->plogi_ack_list
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Downgrade driver to 10.01.00.19-k There
    are upstream bug reports against 10.01.00.19-k which
    haven't been resolved. Also the newer version failed to
    get a proper review. For time being it's better to got
    with the older version and do not introduce new bugs.

  - scsi: qla2xxx: Dual FCP-NVMe target port support
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Enable type checking for the SRB free and
    done callback functions (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix abort timeout race condition
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix a NULL pointer dereference
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix a qla24xx_enable_msix() error path
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix a race condition between aborting and
    completing a SCSI command (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix a recently introduced kernel warning
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix a small typo in qla_bsg.c
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix code indentation for
    qla27xx_fwdt_entry (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix comment alignment in qla_bsg.c
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix comment in MODULE_PARM_DESC in
    qla2xxx (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix different size DMA Alloc/Unmap
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix DMA error when the DIF sg buffer
    crosses 4GB boundary (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix DMA unmap leak (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix driver reload for ISP82xx
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix driver unload when FC-NVMe LUNs are
    connected (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: fix fcport NULL pointer access
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix flash read for Qlogic ISPs
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix formatting of pointer types
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix fw dump corruption (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix fw options handle eh_bus_reset()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix gnl.l memory leak on adapter init
    failure (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix hang in fcport delete path
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix hardirq-unsafe locking (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix hardlockup in abort command during
    driver remove (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix kernel crash after disconnecting NVMe
    devices (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix LUN discovery if loop id is not
    assigned yet by firmware (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix message indicating vectors used by
    driver (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix N2N link reset (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix N2N link up fail (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix Nport ID display value (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix NULL pointer crash due to stale CPUID
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix NVME cmd and LS cmd timeout race
    condition (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix NVMe port discovery after a short
    device port loss (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix panic from use after free in
    qla2x00_async_tm_cmd (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix possible fcport NULL pointer
    dereferences (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix premature timer expiration
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix qla24xx_process_bidir_cmd()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix race conditions in the code for
    aborting SCSI commands (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix read offset in
    qla24xx_load_risc_flash() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Fix Relogin to prevent modifying
    scan_state flag (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix routine qla27xx_dump_(mpi|ram)()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix session cleanup hang (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix session lookup in qlt_abort_work()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: fix spelling mistake 'alredy' ->
    'already' (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: fix spelling mistake 'initializatin' ->
    'initialization' (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix SRB allocation flag to avoid sleeping
    in IRQ context (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix stale mem access on driver unload
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix stale session (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix stuck login session (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix unbound sleep in fcport delete path
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix unload when NVMe devices are
    configured (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Fix use-after-free issues in
    qla2xxx_qpair_sp_free_dma() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: flush IO on chip reset or sess delete
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Further limit FLASH region write access
    from SysFS (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Improve Linux kernel coding style
    conformance (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Improve logging for scan thread
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Include the <asm/unaligned.h> header file
    from qla_dsd.h (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Increase the max_sgl_segments to 1024
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Increase the size of the mailbox arrays
    from 4 to 8 (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Inline the qla2x00_fcport_event_handler()
    function (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Insert spaces where required (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Introduce qla2x00_els_dcmd2_free()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Introduce qla2xxx_get_next_handle()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Introduce the be_id_t and le_id_t data
    types for FC src/dst IDs (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Introduce the dsd32 and dsd64 data
    structures (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Introduce the function qla2xxx_init_sp()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Leave a blank line after declarations
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Let the compiler check the type of the
    SCSI command context pointer (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Log the status code if a firmware command
    fails (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Make it explicit that ELS pass-through
    IOCBs use little endian (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Make qla24xx_async_abort_cmd() static
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Make qla2x00_abort_srb() again decrease
    the sp reference count (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Make qla2x00_mem_free() easier to verify
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Make qla2x00_process_response_queue()
    easier to read (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Make qlt_handle_abts_completion() more
    robust (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Make sure that aborted commands are freed
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Modify NVMe include directives
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move debug messages before sending srb
    preventing panic (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: move IO flush to the front of NVME rport
    unregistration (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move marker request behind QPair
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move qla2x00_clear_loop_id() from
    qla_inline.h into qla_init.c (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Move qla2x00_is_reserved_id() from
    qla_inline.h into qla_init.c (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Move qla2x00_set_fcport_state() from a .h
    into a .c file (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move qla2x00_set_reserved_loop_ids()
    definition (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move the <linux/io-64-nonatomic-lo-hi.h>
    include directive (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Move the port_state_str definition from a
    .h to a .c file (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: no need to check return value of
    debugfs_create functions (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: on session delete, return nvme cmd
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Optimize NPIV tear down process
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Pass little-endian values to the firmware
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Prevent memory leak for CT req/rsp
    allocation (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Prevent multiple ADISC commands per
    session (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Prevent SysFS access when chip is down
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: qla2x00_alloc_fw_dump: set ha->eft
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Really fix qla2xxx_eh_abort()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Reduce the number of casts in GID list
    code (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Reduce the number of forward declarations
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Reduce the scope of three local variables
    in qla2xxx_queuecommand() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Reject
    EH_(abort|device_reset|target_request) (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove a comment that refers to the SCSI
    host lock (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove an include directive from qla_mr.c
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove a set-but-not-used variable
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove a superfluous forward declaration
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove a superfluous pointer check
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove dead code (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: remove double assignment in
    qla2x00_update_fcport (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Remove FW default template (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove qla_tgt_cmd.data_work and
    qla_tgt_cmd.data_work_free (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Remove qla_tgt_cmd.released (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: remove redundant null check on pointer
    sess (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove set but not used variable
    'ptr_dma' (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove superfluous sts_entry_* casts
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove the fcport test from
    qla_nvme_abort_work() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Remove two superfluous casts (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove two superfluous if-tests
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove two superfluous tests (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove unnecessary locking from the
    target code (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove unnecessary null check
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove unreachable code from
    qla83xx_idc_lock() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Remove useless set memory to zero use
    memset() (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Remove WARN_ON_ONCE in
    qla2x00_status_cont_entry() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Replace vmalloc + memset with vzalloc
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Report invalid mailbox status codes
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Report the firmware status code if a
    mailbox command fails (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Reset the FCF_ASYNC_(SENT|ACTIVE) flags
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Restore FAWWPN of Physical Port only for
    loop down (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Retry fabric Scan on IOCB queue full
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Rework key encoding in
    qlt_find_host_by_d_id() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Secure flash update support for ISP28XX
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Set remote port devloss timeout to 0
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Set remove flag for all VP (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Set the qpair in SRB to NULL when SRB is
    released (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Set the responder mode if appropriate for
    ELS pass-through IOCBs (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Set the SCSI command result before
    calling the command done (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Silence fwdump template message
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Silence Successful ELS IOCB message
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplification of register address used
    in qla_tmpl.c (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify a debug statement (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify conditional check again
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify qla24xx_abort_sp_done()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify qla24xx_async_abort_cmd()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify qlt_lport_dump() (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Simplify qlt_send_term_imm_notif()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Skip FW dump on LOOP initialization error
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Suppress a Coveritiy complaint about
    integer overflow (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Suppress multiple Coverity complaint
    about out-of-bounds accesses (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: target: Fix offline port handling and
    host reset handling (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Uninline qla2x00_init_timer()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Unregister resources in the opposite
    order of the registration order (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.00.00.13-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.00.00.14-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.01.00.15-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.01.00.16-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.01.00.18-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.01.00.19-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update driver version to 10.01.00.20-k
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Update flash read/write routine
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use an on-stack completion in
    qla24xx_control_vp() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Use ARRAY_SIZE() in the definition of
    QLA_LAST_SPEED (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use common update-firmware-options
    routine for ISP27xx+ (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Use complete switch scan for RSCN events
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use Correct index for Q-Pair array
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use dma_pool_zalloc() (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use get/put_unaligned where appropriate
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use __le64 instead of uint32_t for
    sending DMA addresses to firmware (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use memcpy() and strlcpy() instead of
    strcpy() and strncpy() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Use mutex protection during
    qla2x00_sysfs_read_fw_dump() (bsc#1123034 bsc#1131304
    bsc#1127988).

  - scsi: qla2xxx: Use strlcpy() instead of strncpy()
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use tabs instead of spaces for
    indentation (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Use tabs to indent code (bsc#1123034
    bsc#1131304 bsc#1127988).

  - scsi: qla2xxx: Verify locking assumptions at runtime
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: scsi_dh_rdac: zero cdb in send_mode_select()
    (bsc#1149313).

  - scsi: scsi_transport_fc: nvme: display FC-NVMe port
    roles (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi: tcm_qla2xxx: Minimize #include directives
    (bsc#1123034 bsc#1131304 bsc#1127988).

  - scsi_transport_fc: complete requests from ->timeout
    (bsc#1142076).

  - sctp: fix the transport error_count check
    (networking-stable-19_08_21).

  - secure boot lockdown: Fix-up backport of /dev/mem access
    restriction The upstream-submitted patch set has evolved
    over time, align our patches (contents and description)
    to reflect the current status as far as /dev/mem access
    is concerned.

  - sky2: Disable MSI on yet another ASUS boards (P6Xxxx)
    (bsc#1051510).

  - slip: make slhc_free() silently accept an error pointer
    (bsc#1051510).

  - slip: sl_alloc(): remove unused parameter 'dev_t line'
    (bsc#1051510).

  - spi: spi-fsl-dspi: Exit the ISR with IRQ_NONE when it's
    not ours (bsc#1111666).

  - SUNRPC fix regression in umount of a secure mount
    (git-fixes).

  - SUNRPC: Handle connection breakages correctly in
    call_status() (git-fixes).

  - SUNRPC/nfs: Fix return value for
    nfs4_callback_compound() (git-fixes).

  - supported.conf: Add vfio_ccw (bsc#1151192 jsc#SLE-6138).

  - supported.conf: Mark vfio_ccw supported by SUSE, because
    bugs can be routed to IBM via SUSE support
    (jsc#SLE-6138, bsc#1151192).

  - tcp: make sure EPOLLOUT wont be missed
    (networking-stable-19_08_28).

  - team: Add vlan tx offload to hw_enc_features
    (bsc#1051510).

  - team: Add vlan tx offload to hw_enc_features
    (networking-stable-19_08_21).

  - tpm_tis_core: Set TPM_CHIP_FLAG_IRQ before probing for
    interrupts (bsc#1082555).

  - tty: serial: fsl_lpuart: Use appropriate lpuart32_* I/O
    funcs (bsc#1111666).

  - tun: fix use-after-free when register netdev failed
    (bsc#1111666).

  - Update patches.suse/ext4-unsupported-features.patch
    (SLE-8615, bsc#1149651, SLE-9243).

  - Update
    patches.suse/powerpc-powernv-Return-for-invalid-IMC-doma
    in.patch (bsc#1054914, git-fixes).

  - Update s390 config files (bsc#1151192). - VFIO_CCW=m -
    S390_CCW_IOMMU=y

  - USB: usbcore: Fix slab-out-of-bounds bug during device
    reset (bsc#1051510).

  - vhost/test: fix build for vhost test (bsc#1111666).

  - video: ssd1307fb: Start page range at page_offset
    (bsc#1113722)

  - wcn36xx: use dynamic allocation for large variables
    (bsc#1111666).

  - x86/CPU/AMD: Clear RDRAND CPUID bit on AMD family
    15h/16h (bsc#1114279).

  - x86/fpu: Add FPU state copying quirk to handle XRSTOR
    failure on Intel Skylake CPUs (bsc#1151955).

  - x86/tls: Fix possible spectre-v1 in do_get_thread_area()
    (bsc#1114279).

  - xen/netback: Reset nr_frags before freeing skb
    (networking-stable-19_08_21).

  - xen-netfront: do not assume sk_buff_head list is empty
    in error handling (bsc#1065600).

  - xen-netfront: do not use ~0U as error return value for
    xennet_fill_frags() (bsc#1065600).

  - xen/xenbus: fix self-deadlock after killing user process
    (bsc#1065600).

  - xsk: avoid store-tearing when assigning queues
    (bsc#1111666).

  - xsk: avoid store-tearing when assigning umem
    (bsc#1111666)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.20.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
