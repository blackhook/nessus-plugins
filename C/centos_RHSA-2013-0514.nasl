#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0514 and 
# CentOS Errata and Security Advisory 2013:0514 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65146);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688");
  script_bugtraq_id(51954, 54638, 55297);
  script_xref(name:"RHSA", value:"2013:0514");

  script_name(english:"CentOS 6 : php (CESA-2013:0514)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix three security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for
a remote attacker to perform SQL injection attacks. (CVE-2012-0831)

These updated php packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of php are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?024d6295"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e421e893"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2688");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-22.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-22.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}
