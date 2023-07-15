#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0191. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20855);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2002-2185", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0124", "CVE-2005-0400", "CVE-2005-0815", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806");
  script_xref(name:"RHSA", value:"2006:0191");

  script_name(english:"RHEL 2.1 : kernel (RHSA-2006:0191)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix a number of security issues as well
as other bugs are now available for Red Hat Enterprise Linux 2.1 (32
bit architectures)

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

  - a flaw in network IGMP processing that a allowed a
    remote user on the local network to cause a denial of
    service (disabling of multicast reports) if the system
    is running multicast applications (CVE-2002-2185,
    moderate)

  - a race condition that allowed local users to read the
    environment variables of another process (CVE-2004-1058,
    low)

  - a flaw in the open_exec function of execve that allowed
    a local user to read setuid ELF binaries that should
    otherwise be protected by standard permissions.
    (CVE-2004-1073, moderate). Red Hat originally reported
    this flaw as being fixed by RHSA-2004:504, but a patch
    for this issue was missing from that update.

  - a flaw in the coda module that allowed a local user to
    cause a denial of service (crash) or possibly gain
    privileges (CVE-2005-0124, moderate)

  - a potential leak of kernel data from ext2 file system
    handling (CVE-2005-0400, low)

  - flaws in ISO-9660 file system handling that allowed the
    mounting of an invalid image on a CD-ROM to cause a
    denial of service (crash) or potentially execute
    arbitrary code (CVE-2005-0815, moderate)

  - a flaw in gzip/zlib handling internal to the kernel that
    may allow a local user to cause a denial of service
    (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2709, moderate)

  - a flaw in IPv6 network UDP port hash table lookups that
    allowed a local user to cause a denial of service (hang)
    (CVE-2005-2973, important)

  - a network buffer info leak using the orinoco driver that
    allowed a remote user to possibly view uninitialized
    data (CVE-2005-3180, important)

  - a flaw in IPv4 network TCP and UDP netfilter handling
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-3275, important)

  - a flaw in the IPv6 flowlabel code that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-3806, important)

The following bugs were also addressed :

  - Handle set_brk() errors in binfmt_elf/aout

  - Correct error handling in shmem_ioctl

  - Correct scsi error return

  - Fix netdump time keeping bug

  - Fix netdump link-down freeze

  - Fix FAT fs deadlock

All Red Hat Enterprise Linux 2.1 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2002-2185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0191"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-summit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2002-2185", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0124", "CVE-2005-0400", "CVE-2005-0815", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3180", "CVE-2005-3275", "CVE-2005-3806");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2006:0191");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0191";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-BOOT-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-debug-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-doc-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-enterprise-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-headers-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-smp-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kernel-source-2.4.9-e.68")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i686", reference:"kernel-summit-2.4.9-e.68")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debug / kernel-doc / etc");
  }
}
