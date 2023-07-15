#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0676. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108984);
  script_version("1.13");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2016-3672", "CVE-2016-7913", "CVE-2016-8633", "CVE-2017-1000252", "CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-12154", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-13305", "CVE-2017-14140", "CVE-2017-15116", "CVE-2017-15121", "CVE-2017-15126", "CVE-2017-15127", "CVE-2017-15129", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-17053", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17558", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-7294", "CVE-2017-8824", "CVE-2017-9725", "CVE-2018-1000004", "CVE-2018-5750", "CVE-2018-6927");
  script_xref(name:"RHSA", value:"2018:0676");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2018:0676)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel-rt is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-rt packages provide the Real Time Linux Kernel, which
enables fine-tuning for systems with extremely high determinism
requirements.

Security Fix(es) :

* kernel: Buffer overflow in firewire driver via crafted incoming
packets (CVE-2016-8633, Important)

* kernel: Use-after-free vulnerability in DCCP socket (CVE-2017-8824,
Important)

* Kernel: kvm: nVMX: L2 guest could access hardware(L0) CR8 register
(CVE-2017-12154, Important)

* kernel: v4l2: disabled memory access protection mechanism allowing
privilege escalation (CVE-2017-13166, Important)

* kernel: media: use-after-free in [tuner-xc2028] media driver
(CVE-2016-7913, Moderate)

* kernel: drm/vmwgfx: fix integer overflow in
vmw_surface_define_ioctl() (CVE-2017-7294, Moderate)

* kernel: Incorrect type conversion for size during dma allocation
(CVE-2017-9725, Moderate)

* kernel: memory leak when merging buffers in SCSI IO vectors
(CVE-2017-12190, Moderate)

* kernel: vfs: BUG in truncate_inode_pages_range() and fuse client
(CVE-2017-15121, Moderate)

* kernel: Use-after-free in userfaultfd_event_wait_completion function
in userfaultfd.c (CVE-2017-15126, Moderate)

* kernel: net: double-free and memory corruption in get_net_ns_by_id()
(CVE-2017-15129, Moderate)

* kernel: Use-after-free in snd_seq_ioctl_create_port()
(CVE-2017-15265, Moderate)

* kernel: Incorrect handling in arch/x86/include/asm/
mmu_context.h:init_new_context function allowing use-after-free
(CVE-2017-17053, Moderate)

* kernel: Missing capabilities check in
net/netfilter/nfnetlink_cthelper.c allows for unprivileged access to
systemwide nfnl_cthelper_list structure (CVE-2017-17448, Moderate)

* kernel: Missing namespace check in net/netlink/af_netlink.c allows
for network monitors to observe systemwide activity (CVE-2017-17449,
Moderate)

* kernel: Unallocated memory access by malicious USB device via
bNumInterfaces overflow (CVE-2017-17558, Moderate)

* kernel: netfilter: use-after-free in tcpmss_mangle_packet function
in net/ netfilter/xt_TCPMSS.c (CVE-2017-18017, Moderate)

* kernel: Race condition in drivers/md/dm.c:dm_get_from_kobject()
allows local users to cause a denial of service (CVE-2017-18203,
Moderate)

* kernel: kvm: Reachable BUG() on out-of-bounds guest IRQ
(CVE-2017-1000252, Moderate)

* Kernel: KVM: DoS via write flood to I/O port 0x80 (CVE-2017-1000407,
Moderate)

* kernel: Stack information leak in the EFS element (CVE-2017-1000410,
Moderate)

* kernel: Kernel address information leak in drivers/acpi/
sbshc.c:acpi_smbus_hc_add() function potentially allowing KASLR bypass
(CVE-2018-5750, Moderate)

* kernel: Race condition in sound system can lead to denial of service
(CVE-2018-1000004, Moderate)

* kernel: unlimiting the stack disables ASLR (CVE-2016-3672, Low)

* kernel: Missing permission check in move_pages system call
(CVE-2017-14140, Low)

* kernel: NULL pointer dereference in rngapi_reset function
(CVE-2017-15116, Low)

* kernel: Improper error handling of VM_SHARED hugetlbfs mapping in
mm/ hugetlb.c (CVE-2017-15127, Low)

* kernel: Integer overflow in futex.c:futux_requeue can lead to denial
of service or unspecified impact (CVE-2018-6927, Low)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Eyal Itkin for reporting CVE-2016-8633;
Mohamed Ghannam for reporting CVE-2017-8824; Jim Mattson (Google.com)
for reporting CVE-2017-12154; Vitaly Mayatskih for reporting
CVE-2017-12190; Andrea Arcangeli (Engineering) for reporting
CVE-2017-15126; Kirill Tkhai for reporting CVE-2017-15129; Jan H.
Schonherr (Amazon) for reporting CVE-2017-1000252; and Armis Labs for
reporting CVE-2017-1000410. The CVE-2017-15121 issue was discovered by
Miklos Szeredi (Red Hat) and the CVE-2017-15116 issue was discovered
by ChunYu Wang (Red Hat).

Additional Changes :

See the Red Hat Enterprise Linux 7.5 Release Notes linked from
References."
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-8824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-9725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-13166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-13305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-14140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-17448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-17449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-17558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-18017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-18203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1000004"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-3672", "CVE-2016-7913", "CVE-2016-8633", "CVE-2017-1000252", "CVE-2017-1000407", "CVE-2017-1000410", "CVE-2017-12154", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-13305", "CVE-2017-14140", "CVE-2017-15116", "CVE-2017-15121", "CVE-2017-15126", "CVE-2017-15127", "CVE-2017-15129", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-17053", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17558", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-7294", "CVE-2017-8824", "CVE-2017-9725", "CVE-2018-1000004", "CVE-2018-5750", "CVE-2018-6927");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:0676");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0676";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-debuginfo-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-rt-doc-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-debuginfo-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-3.10.0-862.rt56.804.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-debuginfo-3.10.0-862.rt56.804.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
