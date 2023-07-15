#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2728 and 
# Oracle Linux Security Advisory ELSA-2017-2728 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103238);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7546", "CVE-2017-7547");
  script_xref(name:"RHSA", value:"2017:2728");

  script_name(english:"Oracle Linux 7 : postgresql (ELSA-2017-2728)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2728 :

An update for postgresql is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

The following packages have been upgraded to a later upstream version:
postgresql (9.2.23). (BZ#1484639, BZ#1484647)

Security Fix(es) :

* It was found that authenticating to a PostgreSQL database account
with an empty password was possible despite libpq's refusal to send an
empty password. A remote attacker could potentially use this flaw to
gain access to database accounts with empty passwords. (CVE-2017-7546)

* An authorization flaw was found in the way PostgreSQL handled access
to the pg_user_mappings view on foreign servers. A remote,
authenticated attacker could potentially use this flaw to retrieve
passwords from the user mappings defined by the foreign server owners
without actually having the privileges to do so. (CVE-2017-7547)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Ben de Graaff, Jelte Fennema, and Jeroen
van der Ham as the original reporters of CVE-2017-7546; and Jeff Janes
as the original reporter of CVE-2017-7547."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-September/007209.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-contrib-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-devel-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-docs-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-libs-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plperl-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-plpython-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-server-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-static-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-test-9.2.23-1.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.23-1.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
