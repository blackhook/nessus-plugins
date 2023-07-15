#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-930.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102510);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-8831");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-930)");
  script_summary(english:"Check for the openSUSE-2017-930 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000111: Fixed a race condition in net-packet
    code that could be exploited to cause out-of-bounds
    memory access (bsc#1052365).

  - CVE-2017-1000112: Fixed a race condition in net-packet
    code that could have been exploited by unprivileged
    users to gain root access. (bsc#1052311).

  - CVE-2017-8831: The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds array access) or possibly have
    unspecified other impact by changing a certain
    sequence-number value, aka a 'double fetch'
    vulnerability (bnc#1037994).

The following non-security bugs were fixed :

  - acpi/nfit: Add support of NVDIMM memory error
    notification in ACPI 6.2 (bsc#1052325).

  - acpi/nfit: Issue Start ARS to retrieve existing records
    (bsc#1052325).

  - bcache: force trigger gc (bsc#1038078).

  - bcache: only recovery I/O error for writethrough mode
    (bsc#1043652).

  - block: do not allow updates through sysfs until
    registration completes (bsc#1047027).

  - config: disable CONFIG_RT_GROUP_SCHED (bsc#1052204).

  - drivers: hv: : As a bandaid, increase HV_UTIL_TIMEOUT
    from 30 to 60 seconds (bnc#1039153)

  - drivers: hv: Fix a typo (fate#320485).

  - drivers: hv: util: Make hv_poll_channel() a little more
    efficient (fate#320485).

  - drivers: hv: vmbus: Close timing hole that can corrupt
    per-cpu page (fate#320485).

  - drivers: hv: vmbus: Fix error code returned by
    vmbus_post_msg() (fate#320485).

  - Fix kABI breakage with CONFIG_RT_GROUP_SCHED=n
    (bsc#1052204).

  - hv_netvsc: change netvsc device default duplex to FULL
    (fate#320485).

  - hv_netvsc: Fix the carrier state error when data path is
    off (fate#320485).

  - hv_netvsc: Remove unnecessary var link_state from struct
    netvsc_device_info (fate#320485).

  - hyperv: fix warning about missing prototype
    (fate#320485).

  - hyperv: netvsc: Neaten netvsc_send_pkt by using a
    temporary (fate#320485).

  - hyperv: remove unnecessary return variable
    (fate#320485).

  - i40e/i40evf: Fix use after free in Rx cleanup path
    (bsc#1051689).

  - IB/hfi1: Wait for QSFP modules to initialize
    (bsc#1019151).

  - ibmvnic: Check for transport event on driver resume
    (bsc#1051556, bsc#1052709).

  - ibmvnic: Initialize SCRQ's during login renegotiation
    (bsc#1052223).

  - ibmvnic: Report rx buffer return codes as netdev_dbg
    (bsc#1052794).

  - iommu/amd: Enable ga_log_intr when enabling guest_mode
    (bsc1052533).

  - iommu/amd: Fix schedule-while-atomic BUG in
    initialization code (bsc1052533).

  - KABI protect struct acpi_nfit_desc (bsc#1052325).

  - kabi/severities: add drivers/scsi/hisi_sas to kabi
    severities

  - libnvdimm: fix badblock range handling of ARS range
    (bsc#1023175).

  - libnvdimm, pmem: fix a NULL pointer BUG in
    nd_pmem_notify (bsc#1023175).

  - net: add netdev_lockdep_set_classes() helper
    (fate#320485).

  - net: hyperv: use new api
    ethtool_(get|set)_link_ksettings (fate#320485).

  - net/mlx4_core: Fixes missing capability bit in flags2
    capability dump (bsc#1015337).

  - net/mlx4_core: Fix namespace misalignment in QinQ VST
    support commit (bsc#1015337).

  - net/mlx4_core: Fix sl_to_vl_change bit offset in flags2
    dump (bsc#1015337).

  - netsvc: Remove upstream commit e14b4db7a567 netvsc: fix
    race during initialization will be replaced by following
    changes

  - netsvc: Revert 'netvsc: optimize calculation of number
    of slots' (fate#320485).

  - netvsc: add comments about callback's and NAPI
    (fate#320485).

  - netvsc: Add #include's for csum_* function declarations
    (fate#320485).

  - netvsc: add rtnl annotations in rndis (fate#320485).

  - netvsc: add some rtnl_dereference annotations
    (fate#320485).

  - netvsc: avoid race with callback (fate#320485).

  - netvsc: change logic for change mtu and set_queues
    (fate#320485).

  - netvsc: change max channel calculation (fate#320485).

  - netvsc: change order of steps in setting queues
    (fate#320485).

  - netvsc: Deal with rescinded channels correctly
    (fate#320485).

  - netvsc: do not access netdev->num_rx_queues directly
    (fate#320485).

  - netvsc: do not overload variable in same function
    (fate#320485).

  - netvsc: do not print pointer value in error message
    (fate#320485).

  - netvsc: eliminate unnecessary skb == NULL checks
    (fate#320485).

  - netvsc: enable GRO (fate#320485).

  - netvsc: Fix a bug in sub-channel handling (fate#320485).

  - netvsc: fix and cleanup rndis_filter_set_packet_filter
    (fate#320485).

  - netvsc: fix calculation of available send sections
    (fate#320485).

  - netvsc: fix dereference before null check errors
    (fate#320485).

  - netvsc: fix error unwind on device setup failure
    (fate#320485).

  - netvsc: fix hang on netvsc module removal (fate#320485).

  - netvsc: fix NAPI performance regression (fate#320485).

  - netvsc: fix net poll mode (fate#320485).

  - netvsc: fix netvsc_set_channels (fate#320485).

  - netvsc: fix ptr_ret.cocci warnings (fate#320485).

  - netvsc: fix rcu dereference warning from ethtool
    (fate#320485).

  - netvsc: fix RCU warning in get_stats (fate#320485).

  - netvsc: fix return value for set_channels (fate#320485).

  - netvsc: fix rtnl deadlock on unregister of vf
    (fate#320485, bsc#1052442).

  - netvsc: fix use after free on module removal
    (fate#320485).

  - netvsc: fix warnings reported by lockdep (fate#320485).

  - netvsc: fold in get_outbound_net_device (fate#320485).

  - netvsc: force link update after MTU change
    (fate#320485).

  - netvsc: handle offline mtu and channel change
    (fate#320485).

  - netvsc: implement NAPI (fate#320485).

  - netvsc: include rtnetlink.h (fate#320485).

  - netvsc: Initialize all channel related state prior to
    opening the channel (fate#320485).

  - netvsc: make sure and unregister datapath (fate#320485,
    bsc#1052899).

  - netvsc: make sure napi enabled before vmbus_open
    (fate#320485).

  - netvsc: mark error cases as unlikely (fate#320485).

  - netvsc: move filter setting to rndis_device
    (fate#320485).

  - netvsc: need napi scheduled during removal
    (fate#320485).

  - netvsc: need rcu_derefence when accessing internal
    device info (fate#320485).

  - netvsc: optimize calculation of number of slots
    (fate#320485).

  - netvsc: optimize receive completions (fate#320485).

  - netvsc: pass net_device to netvsc_init_buf and
    netvsc_connect_vsp (fate#320485).

  - netvsc: prefetch the first incoming ring element
    (fate#320485).

  - netvsc: Properly initialize the return value
    (fate#320485).

  - netvsc: remove bogus rtnl_unlock (fate#320485).

  - netvsc: remove no longer used max_num_rss queues
    (fate#320485).

  - netvsc: Remove redundant use of ipv6_hdr()
    (fate#320485).

  - netvsc: remove unnecessary indirection of page_buffer
    (fate#320485).

  - netvsc: remove unnecessary lock on shutdown
    (fate#320485).

  - netvsc: remove unused #define (fate#320485).

  - netvsc: replace netdev_alloc_skb_ip_align with
    napi_alloc_skb (fate#320485).

  - netvsc: save pointer to parent netvsc_device in channel
    table (fate#320485).

  - netvsc: signal host if receive ring is emptied
    (fate#320485).

  - netvsc: transparent VF management (fate#320485,
    bsc#1051979).

  - netvsc: use ERR_PTR to avoid dereference issues
    (fate#320485).

  - netvsc: use hv_get_bytes_to_read (fate#320485).

  - netvsc: use napi_consume_skb (fate#320485).

  - netvsc: use RCU to protect inner device structure
    (fate#320485).

  - netvsc: uses RCU instead of removal flag (fate#320485).

  - netvsc: use typed pointer for internal state
    (fate#320485).

  - nvme: fabrics commands should use the fctype field for
    data direction (bsc#1043805).

  - powerpc/perf: Fix SDAR_MODE value for continous sampling
    on Power9 (bsc#1053043 (git-fixes)).

  - powerpc/tm: Fix saving of TM SPRs in core dump
    (fate#318470, git-fixes 08e1c01d6aed).

  - qeth: fix L3 next-hop im xmit qeth hdr (bnc#1052773,
    LTC#157374).

  - rdma/bnxt_re: checking for NULL instead of IS_ERR()
    (bsc#1052925).

  - scsi: aacraid: fix PCI error recovery path
    (bsc#1048912).

  - scsi_devinfo: fixup string compare (bsc#1037404).

  - scsi_dh_alua: suppress errors from unsupported devices
    (bsc#1038792).

  - scsi: hisi_sas: add pci_dev in hisi_hba struct
    (bsc#1049298).

  - scsi: hisi_sas: add v2 hw internal abort timeout
    workaround (bsc#1049298).

  - scsi: hisi_sas: controller reset for multi-bits ECC and
    AXI fatal errors (bsc#1049298).

  - scsi: hisi_sas: fix NULL deference when TMF timeouts
    (bsc#1049298).

  - scsi: hisi_sas: fix timeout check in
    hisi_sas_internal_task_abort() (bsc#1049298).

  - scsi: hisi_sas: optimise DMA slot memory (bsc#1049298).

  - scsi: hisi_sas: optimise the usage of hisi_hba.lock
    (bsc#1049298).

  - scsi: hisi_sas: relocate get_ata_protocol()
    (bsc#1049298).

  - scsi: hisi_sas: workaround a SoC SATA IO processing bug
    (bsc#1049298).

  - scsi: hisi_sas: workaround SoC about abort timeout bug
    (bsc#1049298).

  - scsi: hisi_sas: workaround STP link SoC bug
    (bsc#1049298).

  - scsi: lpfc: do not double count abort errors
    (bsc#1048912).

  - scsi: lpfc: fix linking against modular NVMe support
    (bsc#1048912).

  - scsi: qedi: Fix return code in qedi_ep_connect()
    (bsc#1048912).

  - scsi: storvsc: Prefer kcalloc over kzalloc with multiply
    (fate#320485).

  - scsi: storvsc: remove return at end of void function
    (fate#320485).

  - tools: hv: Add clean up for included files in Ubuntu net
    config (fate#320485).

  - tools: hv: Add clean up function for Ubuntu config
    (fate#320485).

  - tools: hv: properly handle long paths (fate#320485).

  - tools: hv: set allow-hotplug for VF on Ubuntu
    (fate#320485).

  - tools: hv: set hotplug for VF on Suse (fate#320485).

  - tools: hv: vss: Thaw the filesystem and continue if
    freeze call has timed out (fate#320485).

  - vfs: fix missing inode_get_dev sites (bsc#1052049).

  - vmbus: cleanup header file style (fate#320485).

  - vmbus: expose debug info for drivers (fate#320485).

  - vmbus: fix spelling errors (fate#320485).

  - vmbus: introduce in-place packet iterator (fate#320485).

  - vmbus: only reschedule tasklet if time limit exceeded
    (fate#320485).

  - vmbus: re-enable channel tasklet (fate#320485).

  - vmbus: remove unnecessary initialization (fate#320485).

  - vmbus: remove useless return's (fate#320485).

  - x86/dmi: Switch dmi_remap() from ioremap() to
    ioremap_cache() (bsc#1051399).

  - x86/hyperv: Check frequency MSRs presence according to
    the specification (fate#320485).

  - The package release number was increased to be higher
    than the Leap 42.2 package (boo#1053531)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.79-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.79-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.79-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.79-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
