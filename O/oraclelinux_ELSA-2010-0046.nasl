#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0046 and 
# Oracle Linux Security Advisory ELSA-2010-0046 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67988);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2006-6304", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272");
  script_bugtraq_id(36576, 37019, 37068, 37069, 37339, 37806);
  script_xref(name:"RHSA", value:"2010:0046");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2010-0046)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0046 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* an array index error was found in the gdth driver. A local user
could send a specially crafted IOCTL request that would cause a denial
of service or, possibly, privilege escalation. (CVE-2009-3080,
Important)

* a flaw was found in the FUSE implementation. When a system is low on
memory, fuse_put_request() could dereference an invalid pointer,
possibly leading to a local denial of service or privilege escalation.
(CVE-2009-4021, Important)

* Tavis Ormandy discovered a deficiency in the fasync_helper()
implementation. This could allow a local, unprivileged user to
leverage a use-after-free of locked, asynchronous file descriptors to
cause a denial of service or privilege escalation. (CVE-2009-4141,
Important)

* the Parallels Virtuozzo Containers team reported the RHSA-2009:1243
update introduced two flaws in the routing implementation. If an
attacker was able to cause a large enough number of collisions in the
routing hash table (via specially crafted packets) for the emergency
route flush to trigger, a deadlock could occur. Secondly, if the
kernel routing cache was disabled, an uninitialized pointer would be
left behind after a route lookup, leading to a kernel panic.
(CVE-2009-4272, Important)

* the RHSA-2009:0225 update introduced a rewrite attack flaw in the
do_coredump() function. A local attacker able to guess the file name a
process is going to dump its core to, prior to the process crashing,
could use this flaw to append data to the dumped core file. This issue
only affects systems that have '/proc/sys/fs/suid_dumpable' set to 2
(the default value is 0). (CVE-2006-6304, Moderate)

The fix for CVE-2006-6304 changes the expected behavior: With
suid_dumpable set to 2, the core file will not be recorded if the file
already exists. For example, core files will not be overwritten on
subsequent crashes of processes whose core files map to the same name.

* an information leak was found in the Linux kernel. On AMD64 systems,
32-bit processes could access and read certain 64-bit registers by
temporarily switching themselves to 64-bit mode. (CVE-2009-2910,
Moderate)

* the RHBA-2008:0314 update introduced N_Port ID Virtualization (NPIV)
support in the qla2xxx driver, resulting in two new sysfs pseudo
files, '/sys/class/scsi_host/[a qla2xxx host]/vport_create' and
'vport_delete'. These two files were world-writable by default,
allowing a local user to change SCSI host attributes. This flaw only
affects systems using the qla2xxx driver and NPIV capable hardware.
(CVE-2009-3556, Moderate)

* permission issues were found in the megaraid_sas driver. The
'dbg_lvl' and 'poll_mode_io' files on the sysfs file system ('/sys/')
had world-writable permissions. This could allow local, unprivileged
users to change the behavior of the driver. (CVE-2009-3889,
CVE-2009-3939, Moderate)

* a NULL pointer dereference flaw was found in the firewire-ohci
driver used for OHCI compliant IEEE 1394 controllers. A local,
unprivileged user with access to /dev/fw* files could issue certain
IOCTL calls, causing a denial of service or privilege escalation. The
FireWire modules are blacklisted by default, and if enabled, only root
has access to the files noted above by default. (CVE-2009-4138,
Moderate)

* a buffer overflow flaw was found in the hfs_bnode_read() function in
the HFS file system implementation. This could lead to a denial of
service if a user browsed a specially crafted HFS file system, for
example, by running 'ls'. (CVE-2009-4020, Low)

Bug fix documentation for this update will be available shortly from
www.redhat.com/docs/en-US/errata/RHSA-2010-0046/Kernel_Security_Update
/ index.html

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-January/001335.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2006-6304", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2010-0046");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "2.6";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-164.11.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-164.11.1.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
