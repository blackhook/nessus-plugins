#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0092 and 
# CentOS Errata and Security Advisory 2012:0092 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57807);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_xref(name:"RHSA", value:"2012:0092");

  script_name(english:"CentOS 5 : php53 (CESA-2012:0092)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was discovered that the fix for CVE-2011-4885 (released via
RHSA-2012:0019 for php53 packages in Red Hat Enterprise Linux 5)
introduced an uninitialized memory use flaw. A remote attacker could
send a specially- crafted HTTP request to cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-0830)

All php53 users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ce11cb8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0830");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-1.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-1.el5_7.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53 / php53-bcmath / php53-cli / php53-common / php53-dba / etc");
}
