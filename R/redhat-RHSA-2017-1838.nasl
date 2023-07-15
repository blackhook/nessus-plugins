#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1838. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102142);
  script_version("3.8");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7484", "CVE-2017-7485", "CVE-2017-7486");
  script_xref(name:"RHSA", value:"2017:1838");

  script_name(english:"RHEL 5 : rh-postgresql95-postgresql (RHSA-2017:1838)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for rh-postgresql95-postgresql is now available for Red Hat
Satellite 5.8 and Red Hat Satellite 5.8 ELS.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

This update applies only to Satellite 5.8 instances using either
embedded or managed PostgreSQL databases.

There are manual steps required in order to finish the migration from
postgresql92-postgresql to rh-postgresql95-postgresql. If these steps
are not undertaken, the affected Satellite will continue to use
PostgreSQL 9.2.

postgresql92-postgresql will be upgraded automatically to
rh-postgresql95-postgresql as part of an upgrade to Satellite 5.8.

PostgreSQL is an advanced object-relational database management system
(DBMS).

Security Fix(es) :

* It was found that some selectivity estimation functions did not
check user privileges before providing information from pg_statistic,
possibly leaking information. A non-administrative database user could
use this flaw to steal some information from tables they are otherwise
not allowed to access. (CVE-2017-7484)

* It was discovered that the PostgreSQL client library (libpq) did not
enforce the use of TLS/SSL for a connection to a PostgreSQL server
when the PGREQUIRESSL environment variable was set. An
man-in-the-middle attacker could use this flaw to strip the SSL/TLS
protection from a connection between a client and a server.
(CVE-2017-7485)

* It was found that the pg_user_mappings view could disclose
information about user mappings to a foreign database to
non-administrative database users. A database user with USAGE
privilege for this mapping could, when querying the view, obtain user
mapping data, such as the username and password used to connect to the
foreign database. (CVE-2017-7486)

Red Hat would like to thank the PostgreSQL project for reporting these
issues. Upstream acknowledges Robert Haas as the original reporter of
CVE-2017-7484; Daniel Gustafsson as the original reporter of
CVE-2017-7485; and Andrew Wheelwright as the original reporter of
CVE-2017-7486."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7486.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql95-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5\.8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.8", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1838";
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
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-contrib-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-contrib-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-debuginfo-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-debuginfo-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-libs-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-libs-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-pltcl-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-pltcl-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"s390x", reference:"rh-postgresql95-postgresql-server-9.5.7-2.el6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"8", cpu:"x86_64", reference:"rh-postgresql95-postgresql-server-9.5.7-2.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rh-postgresql95-postgresql / rh-postgresql95-postgresql-contrib / etc");
  }
}
