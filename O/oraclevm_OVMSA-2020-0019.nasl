#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0019.
#

include("compat.inc");

if (description)
{
  script_id(137128);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2016-5244", "CVE-2017-7346", "CVE-2018-5953", "CVE-2019-0139", "CVE-2019-0140", "CVE-2019-0144", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-18806", "CVE-2019-19056", "CVE-2019-19523", "CVE-2019-19527", "CVE-2019-19532", "CVE-2019-9503", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0019)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - KVM: x86: Remove spurious semicolon (Joao Martins)
    [Orabug: 31413782]

  - genirq: Use rcu in kstat_irqs_usr (Eric Dumazet)

  - genirq: Make sparse_irq_lock protect what it should
    protect (Thomas Gleixner) [Orabug: 30953676]

  - genirq: Free irq_desc with rcu (Thomas Gleixner)
    [Orabug: 30953676]

  - qla2xxx: Update driver version to 9.00.00.00.42.0-k1-v2
    (Arun Easi) [Orabug: 30372266]

  - qla2xxx: Fix device discovery when FCP2 device is lost.
    (Arun Easi) [Orabug: 30372266]

  - brcmfmac: add subtype check for event handling in data
    path (John Donnelly) [Orabug: 30776354] (CVE-2019-9503)

  - percpu-refcount: fix reference leak during percpu-atomic
    transition (Douglas Miller) [Orabug: 30867060]

  - blk-mq: Allow timeouts to run while queue is freezing
    (Gabriel Krisman Bertazi) [Orabug: 30867060]

  - fs/dcache.c: fix spin lockup issue on nlru->lock
    (Junxiao Bi) [Orabug: 30953290]

  - jbd2: disable CONFIG_JBD2_DEBUG (Junxiao Bi) [Orabug:
    31234664]

  - mwifiex: pcie: Fix memory leak in
    mwifiex_pcie_alloc_cmdrsp_buf (Navid Emamdoost) [Orabug:
    31246302] (CVE-2019-19056)

  - drm/vmwgfx: limit the number of mip levels in
    vmw_gb_surface_define_ioctl (Vladis Dronov) [Orabug:
    31262557] (CVE-2017-7346)

  - i40e: Increment the driver version for FW API update
    (Jack Vogel) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: Update FW API version to 1.9 (Piotr Azarewicz)
    [Orabug: 31051191] (CVE-2019-0140) (CVE-2019-0139)
    (CVE-2019-0144)

  - i40e: Changed maximum supported FW API version to 1.8
    (Adam Ludkiewicz) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: Stop dropping 802.1ad tags - eth proto 0x88a8
    (Scott Peterson) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: fix reading LLDP configuration (Mariusz Stachura)
    [Orabug: 31051191] (CVE-2019-0140) (CVE-2019-0139)
    (CVE-2019-0144)

  - i40e: Add capability flag for stopping FW LLDP
    (Krzysztof Galazka) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: refactor FW version checking (Mitch Williams)
    [Orabug: 31051191] (CVE-2019-0140) (CVE-2019-0139)
    (CVE-2019-0144)

  - i40e: shutdown all IRQs and disable MSI-X when suspended
    (Jacob Keller) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: prevent service task from running while we're
    suspended (Jacob Keller) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - i40e: don't clear suspended state until we finish
    resuming (Jacob Keller) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - i40e: use newer generic PM support instead of legacy PM
    callbacks (Jacob Keller) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - i40e: use separate state bit for miscellaneous IRQ setup
    (Jacob Keller) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: fix for flow director counters not wrapping as
    expected (Mariusz Stachura) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - i40e: relax warning message in case of version mismatch
    (Mariusz Stachura) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: simplify member variable accesses (Sudheer
    Mogilappagari) [Orabug: 31051191] (CVE-2019-0140)
    (CVE-2019-0139) (CVE-2019-0144)

  - i40e: Fix link down message when interface is brought up
    (Sudheer Mogilappagari) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - i40e: Fix unqualified module message while bringing link
    up (Sudheer Mogilappagari) [Orabug: 31051191]
    (CVE-2019-0140) (CVE-2019-0139) (CVE-2019-0144)

  - HID: Fix assumption that devices have inputs (Alan
    Stern) [Orabug: 31208622] (CVE-2019-19532)

  - qla2xxx: DBG: disable 3D mailbox. (Quinn Tran) [Orabug:
    30890687]

  - scsi: qla2xxx: Fix mtcp dump collection failure (Quinn
    Tran) [Orabug: 30890687]

  - scsi: qla2xxx: Add Serdes support for ISP27XX (Joe
    Carnuccio) [Orabug: 30890687]

  - vgacon: Fix a UAF in vgacon_invert_region (Zhang Xiaoxu)
    [Orabug: 31143947] (CVE-2020-8649) (CVE-2020-8647)
    (CVE-2020-8647) (CVE-2020-8649) (CVE-2020-8649)
    (CVE-2020-8647)

  - HID: hiddev: do cleanup in failure of opening a device
    (Hillf Danton) [Orabug: 31206360] (CVE-2019-19527)

  - HID: hiddev: avoid opening a disconnected device (Hillf
    Danton) [Orabug: 31206360] (CVE-2019-19527)

  - USB: adutux: fix use-after-free on disconnect (Johan
    Hovold) [Orabug: 31233769] (CVE-2019-19523)

  - ipv4: implement support for NOPREFIXROUTE ifa flag for
    ipv4 address (Paolo Abeni) [Orabug: 30292825]

  - vt: selection, push sel_lock up (Jiri Slaby) [Orabug:
    30923298] (CVE-2020-8648)

  - vt: selection, push console lock down (Jiri Slaby)
    [Orabug: 30923298] (CVE-2020-8648)

  - vt: selection, close sel_buffer race (Jiri Slaby)
    [Orabug: 30923298] (CVE-2020-8648) (CVE-2020-8648)

  - xfs: stop searching for free slots in an inode chunk
    when there are none (Carlos Maiolino) [Orabug: 31030659]

  - xfs: fix up xfs_swap_extent_forks inline extent handling
    (Eric Sandeen) [Orabug: 31032831]

  - xfs: validate sb_logsunit is a multiple of the fs
    blocksize (Darrick J. Wong) [Orabug: 31034071]

  - mwifiex: Fix three heap overflow at parsing element in
    cfg80211_ap_settings (Wen Huang) [Orabug: 31104481]
    (CVE-2019-14814) (CVE-2019-14815) (CVE-2019-14816)
    (CVE-2019-14814) (CVE-2019-14815) (CVE-2019-14816)

  - rds: fix an infoleak in rds_inc_info_copy (Kangjie Lu)
    [Orabug: 30770962] (CVE-2016-5244)

  - xfs: do async inactivation only when fs freezed (Junxiao
    Bi) [Orabug: 30944736]

  - xfs: fix deadlock between shrinker and fs freeze
    (Junxiao Bi) [Orabug: 30944736]

  - xfs: increase the default parallelism levels of pwork
    clients (Junxiao Bi) [Orabug: 30944736]

  - xfs: decide if inode needs inactivation (Junxiao Bi)
    [Orabug: 30944736]

  - xfs: refactor the predicate part of xfs_free_eofblocks
    (Junxiao Bi) [Orabug: 30944736]

  - floppy: check FDC index for errors before assigning it
    (Linus Torvalds) [Orabug: 31067516] (CVE-2020-9383)

  - KVM: x86: clear stale x86_emulate_ctxt->intercept value
    (Vitaly Kuznetsov) [Orabug: 31118691]

  - slcan: Don't transmit uninitialized stack data in
    padding (Richard Palethorpe) [Orabug: 31136753]
    (CVE-2020-11494)

  - rds: transport module should be auto loaded when
    transport is set (Rao Shoaib) [Orabug: 31031928]

  - KVM: X86: Fix NULL deref in vcpu_scan_ioapic (Wanpeng
    Li) [Orabug: 31078882]

  - vhost: Check docket sk_family instead of call getname
    (Eugenio P&eacute rez) [Orabug: 31085993]
    (CVE-2020-10942)

  - Revert 'oled: give panic handler chance to run before
    kexec' (Wengang Wang) [Orabug: 31098797]

  - kernel: cpu.c: fix return in void function
    cpu_smt_disable (Mihai Carabas) [Orabug: 31047871]

  - net: qlogic: Fix memory leak in ql_alloc_large_buffers
    (Navid Emamdoost) [Orabug: 31055327] (CVE-2019-18806)

  - swiotlb: clean up reporting (Kees Cook) [Orabug:
    31085017] (CVE-2018-5953)

  - KVM: x86: Expose more Intel AVX512 feature to guest
    (Luwei Kang) [Orabug: 31085086]

  - x86/cpufeature: Enable new AVX-512 features (Fenghua Yu)
    [Orabug: 31085086]

  - xenbus: req->err should be updated before req->state
    (Dongli Zhang) [Orabug: 30705030]

  - xenbus: req->body should be updated before req->state
    (Dongli Zhang) [Orabug: 30705030]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2020-June/000980.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.39.2.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.39.2.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
