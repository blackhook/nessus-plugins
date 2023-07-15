#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2595. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94558);
  script_version("2.12");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-3492", "CVE-2016-5612", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6662", "CVE-2016-6663", "CVE-2016-8283");
  script_xref(name:"RHSA", value:"2016:2595");

  script_name(english:"RHEL 7 : mariadb (RHSA-2016:2595)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for mariadb is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a newer upstream version:
mariadb (5.5.52). (BZ#1304516, BZ#1377974)

Security Fix(es) :

* It was discovered that the MariaDB logging functionality allowed
writing to MariaDB configuration files. An administrative database
user, or a database user with FILE privileges, could possibly use this
flaw to run arbitrary commands with root privileges on the system
running the database server. (CVE-2016-6662)

* A race condition was found in the way MariaDB performed MyISAM
engine table repair. A database user with shell access to the server
running mysqld could use this flaw to change permissions of arbitrary
files writable by the mysql system user. (CVE-2016-6663)

* This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2016-3492, CVE-2016-5612, CVE-2016-5616, CVE-2016-5624,
CVE-2016-5626, CVE-2016-5629, CVE-2016-8283)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8283"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2595";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-bench-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-bench-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-debuginfo-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-devel-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-embedded-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-embedded-devel-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mariadb-libs-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-server-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-server-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mariadb-test-5.5.52-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mariadb-test-5.5.52-1.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-debuginfo / mariadb-devel / etc");
  }
}
