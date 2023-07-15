#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0002.
#

include("compat.inc");

if (description)
{
  script_id(105521);
  script_version("3.4");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-16525", "CVE-2017-16526", "CVE-2017-16529", "CVE-2017-16530", "CVE-2017-16531", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0002)");
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

  - fuse: Call end_queued_requests after releasing fc->lock
    in fuse_dev_release (Ashish Samant) [Orabug: 26431550]

  - rds: Fix inaccurate accounting of unsignaled wrs in
    rds_ib_xmit_rdma (H&aring kon Bugge) [Orabug: 27097105]

  - rds: Fix inaccurate accounting of unsignaled wrs
    (H&aring kon Bugge) 

  - rds: ib: Fix NULL pointer dereference in debug code
    (H&aring kon Bugge) 

  - bnx2x: fix slowpath null crash (Zhu Yanjun) [Orabug:
    27133587]

  - rds: System panic if RDS netfilter is enabled and
    RDS/TCP is used (Ka-Cheong Poon) [Orabug: 27150029]

  - USB: serial: console: fix use-after-free after failed
    setup (Johan Hovold) [Orabug: 27206830] (CVE-2017-16525)

  - mlx4: Subscribe to PXM notifier (Konrad Rzeszutek Wilk)

  - xen/pci: Add PXM node notifier for PXM (NUMA) changes.
    (Konrad Rzeszutek Wilk)

  - xen/pcifront: Walk the PCI bus after XenStore
    notification (Konrad Rzeszutek Wilk)

  - uwb: properly check kthread_run return value (Andrey
    Konovalov) [Orabug: 27206880] (CVE-2017-16526)

  - ALSA: usb-audio: Check out-of-bounds access by corrupted
    buffer descriptor (Takashi Iwai) [Orabug: 27206923]
    (CVE-2017-16529)

  - USB: uas: fix bug in handling of alternate settings
    (Alan Stern) [Orabug: 27206999] (CVE-2017-16530)

  - USB: fix out-of-bounds in usb_set_configuration (Greg
    Kroah-Hartman) [Orabug: 27207224] (CVE-2017-16531)

  - HID: usbhid: fix out-of-bounds bug (Jaejoong Kim)
    [Orabug: 27207918] (CVE-2017-16533)

  - USB: core: fix out-of-bounds access bug in
    usb_get_bos_descriptor (Alan Stern) [Orabug: 27207970]
    (CVE-2017-16535)

  - [media] cx231xx-cards: fix NULL-deref on missing
    association descriptor (Johan Hovold) [Orabug: 27208047]
    (CVE-2017-16536)

  - Replace max_t with sub_positive in
    dequeue_entity_load_avg (Gayatri Vasudevan) [Orabug:
    27222316]

  - sched/fair: Fix cfs_rq avg tracking underflow (Gayatri
    Vasudevan) 

  - KVM: nVMX: Fix vmx_check_nested_events return value in
    case an event was reinjected to L2 (Liran Alon) [Orabug:
    27250111]

  - KVM: VMX: use kvm_event_needs_reinjection (Wanpeng Li)
    [Orabug: 27250111]

  - KVM: nVMX: Fix pending events injection (Wanpeng Li)
    [Orabug: 27250111]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0a54569"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.14.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.14.2.el6uek")) flag++;

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
