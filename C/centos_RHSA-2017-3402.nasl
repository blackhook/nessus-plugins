#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3402 and 
# CentOS Errata and Security Advisory 2017:3402 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105114);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12172", "CVE-2017-15097");
  script_xref(name:"RHSA", value:"2017:3402");

  script_name(english:"CentOS 7 : postgresql (CESA-2017:3402)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for postgresql is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PostgreSQL is an advanced object-relational database management system
(DBMS).

Security Fix(es) :

* Privilege escalation flaws were found in the initialization scripts
of PostgreSQL. An attacker with access to the postgres user account
could use these flaws to obtain root access on the server machine.
(CVE-2017-12172, CVE-2017-15097)

Note: This patch drops the script privileges from root to the postgres
user. Therefore, this update works properly only if the postgres user
has write access to the postgres' home directory, such as the one in
the default configuration (/var/lib/pgsql).

Red Hat would like to thank the PostgreSQL project for reporting
CVE-2017-12172. The CVE-2017-15097 issue was discovered by Pedro
Barbosa (Red Hat) and the PostgreSQL project. Upstream acknowledges
Antoine Scemama (Brainloop) as the original reporter of these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-December/022690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65b722b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12172");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-contrib-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-devel-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-docs-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-libs-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-plperl-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-plpython-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-pltcl-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-server-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-static-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-test-9.2.23-3.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"postgresql-upgrade-9.2.23-3.el7_4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
