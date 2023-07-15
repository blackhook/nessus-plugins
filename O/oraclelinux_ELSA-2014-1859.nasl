#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1859 and 
# Oracle Linux Security Advisory ELSA-2014-1859 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79369);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5615", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6484", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559");
  script_bugtraq_id(68564, 68573, 68579, 68593, 68611, 69732, 70446, 70451, 70455, 70462, 70486, 70487, 70510, 70511, 70516, 70517, 70530, 70532, 70550);
  script_xref(name:"RHSA", value:"2014:1859");

  script_name(english:"Oracle Linux 5 : mysql55-mysql (ELSA-2014-1859)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1859 :

Updated mysql55-mysql packages that fix several security issues are
now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-2494, CVE-2014-4207, CVE-2014-4243, CVE-2014-4258,
CVE-2014-4260, CVE-2014-4287, CVE-2014-4274, CVE-2014-6463,
CVE-2014-6464, CVE-2014-6469, CVE-2014-6484, CVE-2014-6505,
CVE-2014-6507, CVE-2014-6520, CVE-2014-6530, CVE-2014-6551,
CVE-2014-6555, CVE-2014-6559)

These updated packages upgrade MySQL to version 5.5.40. Refer to the
MySQL Release Notes listed in the References section for a complete
list of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-November/004647.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql55-mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


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

flag = 0;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-5.5.40-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-bench-5.5.40-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-devel-5.5.40-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-libs-5.5.40-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-server-5.5.40-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mysql55-mysql-test-5.5.40-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql55-mysql / mysql55-mysql-bench / mysql55-mysql-devel / etc");
}
