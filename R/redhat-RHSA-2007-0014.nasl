#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0014. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24315);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-4538", "CVE-2006-4813", "CVE-2006-4814", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6106", "CVE-2006-6535");
  script_bugtraq_id(19702, 20379, 20920, 21353, 21522, 21604, 21663, 22316);
  script_xref(name:"RHSA", value:"2007:0014");

  script_name(english:"RHEL 4 : kernel (RHSA-2007:0014)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the get_fdb_entries function of the network bridging
support that allowed a local user to cause a denial of service (crash)
or allow a potential privilege escalation (CVE-2006-5751, Important)

* an information leak in the _block_prepare_write function that
allowed a local user to read kernel memory (CVE-2006-4813, Important)

* an information leak in the copy_from_user() implementation on s390
and s390x platforms that allowed a local user to read kernel memory
(CVE-2006-5174, Important)

* a flaw in the handling of /proc/net/ip6_flowlabel that allowed a
local user to cause a denial of service (infinite loop)
(CVE-2006-5619, Important)

* a flaw in the AIO handling that allowed a local user to cause a
denial of service (panic) (CVE-2006-5754, Important)

* a race condition in the mincore system core that allowed a local
user to cause a denial of service (system hang) (CVE-2006-4814,
Moderate)

* a flaw in the ELF handling on ia64 and sparc architectures which
triggered a cross-region memory mapping and allowed a local user to
cause a denial of service (CVE-2006-4538, Moderate)

* a flaw in the dev_queue_xmit function of the network subsystem that
allowed a local user to cause a denial of service (data corruption)
(CVE-2006-6535, Moderate)

* a flaw in the handling of CAPI messages over Bluetooth that allowed
a remote system to cause a denial of service or potential code
execution. This flaw is only exploitable if a privileged user
establishes a connection to a malicious remote device (CVE-2006-6106,
Moderate)

* a flaw in the listxattr system call that allowed a local user to
cause a denial of service (data corruption) or potential privilege
escalation. To successfully exploit this flaw the existence of a bad
inode is required first (CVE-2006-5753, Moderate)

* a flaw in the __find_get_block_slow function that allowed a local
privileged user to cause a denial of service (CVE-2006-5757, Low)

* various flaws in the supported filesystems that allowed a local
privileged user to cause a denial of service (CVE-2006-5823,
CVE-2006-6053, CVE-2006-6054, CVE-2006-6056, Low)

In addition to the security issues described above, fixes for the
following bugs were included :

* initialization error of the tg3 driver with some BCM5703x network
card

* a memory leak in the audit subsystem

* x86_64 nmi watchdog timeout is too short

* ext2/3 directory reads fail intermittently

Red Hat would like to thank Dmitriy Monakhov and Kostantin Khorenko
for reporting issues fixed in this erratum.

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-4538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-4813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-4814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-6053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-6054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-6056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-6106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-6535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0014"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
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
  cve_list = make_list("CVE-2006-4538", "CVE-2006-4813", "CVE-2006-4814", "CVE-2006-5174", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5753", "CVE-2006-5754", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6106", "CVE-2006-6535");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2007:0014");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0014";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-42.0.8.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-42.0.8.EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
