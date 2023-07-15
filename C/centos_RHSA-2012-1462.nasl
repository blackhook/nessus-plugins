#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1462 and 
# CentOS Errata and Security Advisory 2012:1462 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62921);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0540", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1703", "CVE-2012-1734", "CVE-2012-2749", "CVE-2012-3150", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197");
  script_bugtraq_id(53058, 53067, 53074, 54540, 54547, 54551, 55120, 55990, 56003, 56005, 56017, 56018, 56021, 56027, 56028, 56036, 56041);
  script_xref(name:"RHSA", value:"2012:1462");

  script_name(english:"CentOS 6 : mysql (CESA-2012:1462)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory pages, listed in the References
section. (CVE-2012-1688, CVE-2012-1690, CVE-2012-1703, CVE-2012-2749,
CVE-2012-0540, CVE-2012-1689, CVE-2012-1734, CVE-2012-3163,
CVE-2012-3158, CVE-2012-3177, CVE-2012-3166, CVE-2012-3173,
CVE-2012-3150, CVE-2012-3180, CVE-2012-3167, CVE-2012-3197,
CVE-2012-3160)

These updated packages upgrade MySQL to version 5.1.66. Refer to the
MySQL release notes listed in the References section for a full list
of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-November/018995.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a199ab9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3163");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"mysql-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-bench-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-devel-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-embedded-devel-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-libs-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-server-5.1.66-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mysql-test-5.1.66-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-embedded / etc");
}
