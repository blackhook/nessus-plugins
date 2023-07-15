#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1671 and 
# CentOS Errata and Security Advisory 2014:1671 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78607);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3634");
  script_bugtraq_id(70187, 70243);
  script_xref(name:"RHSA", value:"2014:1671");

  script_name(english:"CentOS 5 / 6 : rsyslog / rsyslog5 (CESA-2014:1671)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rsyslog5 and rsyslog packages that fix one security issue are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rsyslog packages provide an enhanced, multi-threaded syslog daemon
that supports writing to relational databases, syslog/TCP, RFC 3195,
permitted sender lists, filtering on any message part, and fine
grained output format control.

A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog5 and rsyslog users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the update, the rsyslog service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-October/020699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51eeab03"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea896841"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog and / or rsyslog5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3634");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog5-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-gnutls-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-gssapi-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-mysql-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-pgsql-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"rsyslog5-snmp-5.8.12-5.el5_11")) flag++;

if (rpm_check(release:"CentOS-6", reference:"rsyslog-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-gnutls-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-gssapi-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-mysql-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-pgsql-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-relp-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"rsyslog-snmp-5.8.10-9.el6_6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-gnutls / rsyslog-gssapi / rsyslog-mysql / etc");
}
