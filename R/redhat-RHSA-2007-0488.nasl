#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0488. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25605);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-5158", "CVE-2006-7203", "CVE-2007-0773", "CVE-2007-0958", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3104");
  script_bugtraq_id(23870, 24376, 24631);
  script_xref(name:"RHSA", value:"2007:0488");

  script_name(english:"RHEL 4 : kernel (RHSA-2007:0488)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and bugs in
the Red Hat Enterprise Linux 4 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the connection tracking support for SCTP that allowed a
remote user to cause a denial of service by dereferencing a NULL
pointer. (CVE-2007-2876, Important)

* a flaw in the mount handling routine for 64-bit systems that allowed
a local user to cause denial of service (crash). (CVE-2006-7203,
Important)

* a flaw in the IPv4 forwarding base that allowed a local user to
cause an out-of-bounds access. (CVE-2007-2172, Important)

* a flaw in the PPP over Ethernet implementation that allowed a local
user to cause a denial of service (memory consumption) by creating a
socket using connect and then releasing it before the PPPIOCGCHAN
ioctl has been called. (CVE-2007-2525, Important)

* a flaw in the fput ioctl handling of 32-bit applications running on
64-bit platforms that allowed a local user to cause a denial of
service (panic). (CVE-2007-0773, Important)

* a flaw in the NFS locking daemon that allowed a local user to cause
denial of service (deadlock). (CVE-2006-5158, Moderate)

* a flaw in the sysfs_readdir function that allowed a local user to
cause a denial of service by dereferencing a NULL pointer.
(CVE-2007-3104, Moderate)

* a flaw in the core-dump handling that allowed a local user to create
core dumps from unreadable binaries via PT_INTERP. (CVE-2007-0958,
Low)

* a flaw in the Bluetooth subsystem that allowed a local user to
trigger an information leak. (CVE-2007-1353, Low)

In addition, the following bugs were addressed :

* the NFS could recurse on the same spinlock. Also, NFS, under certain
conditions, did not completely clean up Posix locks on a file close,
leading to mount failures.

* the 32bit compatibility didn't return to userspace correct values
for the rt_sigtimedwait system call.

* the count for unused inodes could be incorrect at times, resulting
in dirty data not being written to disk in a timely manner.

* the cciss driver had an incorrect disk size calculation (off-by-one
error) which prevented disk dumps.

Red Hat would like to thank Ilja van Sprundel and the OpenVZ Linux
kernel team for reporting issues fixed in this erratum.

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-7203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-1353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-3104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0488"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2006-5158", "CVE-2006-7203", "CVE-2007-0773", "CVE-2007-0958", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3104");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2007:0488");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0488";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-55.0.2.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-55.0.2.EL")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
