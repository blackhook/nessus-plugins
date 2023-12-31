#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1654 and 
# Oracle Linux Security Advisory ELSA-2014-1654 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78639);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3634");
  script_bugtraq_id(70187, 70243);
  script_xref(name:"RHSA", value:"2014:1654");

  script_name(english:"Oracle Linux 6 : rsyslog7 (ELSA-2014-1654)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1654 :

Updated rsyslog7 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rsyslog7 packages provide an enhanced, multi-threaded syslog
daemon that supports writing to relational databases, syslog/TCP, RFC
3195, permitted sender lists, filtering on any message part, and fine
grained output format control.

A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon or, potentially, execute arbitrary
code as the user running the rsyslog daemon. (CVE-2014-3634)

Red Hat would like to thank Rainer Gerhards of rsyslog upstream for
reporting this issue.

All rsyslog7 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, the rsyslog service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004562.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsyslog7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rsyslog7-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"rsyslog7-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-elasticsearch-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-gnutls-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-gssapi-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-mysql-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-pgsql-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-relp-7.4.10-3.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"rsyslog7-snmp-7.4.10-3.el6_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog7 / rsyslog7-elasticsearch / rsyslog7-gnutls / etc");
}
