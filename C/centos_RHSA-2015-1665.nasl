#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1665 and 
# CentOS Errata and Security Advisory 2015:1665 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85635);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2582", "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-3152", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4757", "CVE-2015-4864");
  script_xref(name:"RHSA", value:"2015:1665");

  script_name(english:"CentOS 7 : mariadb (CESA-2015:1665) (BACKRONYM)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mariadb packages that fix several security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

It was found that the MySQL client library permitted but did not
require a client to use SSL/TLS when establishing a secure connection
to a MySQL server using the '--ssl' option. A man-in-the-middle
attacker could use this flaw to strip the SSL/TLS protection from a
connection between a client and a server. (CVE-2015-3152)

This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2015-0501, CVE-2015-2568, CVE-2015-0499, CVE-2015-2571,
CVE-2015-0433, CVE-2015-0441, CVE-2015-0505, CVE-2015-2573,
CVE-2015-2582, CVE-2015-2620, CVE-2015-2643, CVE-2015-2648,
CVE-2015-4737, CVE-2015-4752, CVE-2015-4757)

These updated packages upgrade MariaDB to version 5.5.44. Refer to the
MariaDB Release Notes listed in the References section for a complete
list of changes.

All MariaDB users should upgrade to these updated packages, which
correct these issues. After installing this update, the MariaDB server
daemon (mysqld) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-August/021345.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?905b3913"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0501");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-bench-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-devel-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-libs-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-server-5.5.44-1.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mariadb-test-5.5.44-1.el7_1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-devel / mariadb-embedded / etc");
}
