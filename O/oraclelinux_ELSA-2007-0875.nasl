#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0875 and 
# Oracle Linux Security Advisory ELSA-2007-0875 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67566);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-3780");
  script_bugtraq_id(25017);
  script_xref(name:"RHSA", value:"2007:0875");

  script_name(english:"Oracle Linux 4 / 5 : mysql (ELSA-2007-0875)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0875 :

Updated mysql packages that fix a security flaw are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

A flaw was discovered in MySQL's authentication protocol. It is
possible for a remote unauthenticated attacker to send a specially
crafted authentication request to the MySQL server causing it to
crash. (CVE-2007-3780)

All users of the MySQL server are advised to upgrade to these updated
packages, which contain a backported patch which fixes this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-August/000310.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-August/000311.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mysql-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mysql-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mysql-bench-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mysql-bench-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mysql-devel-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mysql-devel-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mysql-server-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mysql-server-4.1.20-2.RHEL4.1.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"mysql-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"mysql-bench-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"mysql-devel-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"mysql-server-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"mysql-test-5.0.22-2.1.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server / mysql-test");
}
