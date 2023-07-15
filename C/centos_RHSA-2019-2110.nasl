#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2110 and 
# CentOS Errata and Security Advisory 2019:2110 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128353);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-16881");
  script_xref(name:"RHSA", value:"2019:2110");

  script_name(english:"CentOS 7 : rsyslog (CESA-2019:2110)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for rsyslog is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The rsyslog packages provide an enhanced, multi-threaded syslog
daemon. It supports MySQL, syslog/TCP, RFC 3195, permitted sender
lists, filtering on any message part, and fine-grained control over
output format.

Security Fix(es) :

* rsyslog: imptcp: integer overflow when Octet-Counted TCP Framing is
enabled (CVE-2018-16881)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4931dbc8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16881");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-crypto-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-doc-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-elasticsearch-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-gnutls-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-gssapi-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-kafka-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-libdbi-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmaudit-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmjsonparse-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmkubernetes-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmnormalize-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mmsnmptrapd-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-mysql-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-pgsql-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-relp-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-snmp-8.24.0-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rsyslog-udpspoof-8.24.0-38.el7")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-crypto / rsyslog-doc / rsyslog-elasticsearch / etc");
}
