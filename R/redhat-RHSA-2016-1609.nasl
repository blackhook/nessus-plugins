#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1609. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92940);
  script_version("2.14");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2016-5385");
  script_xref(name:"RHSA", value:"2016:1609");

  script_name(english:"RHEL 6 : php (RHSA-2016:1609) (httpoxy)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for php is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5385)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5385"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1609";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-48.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-48.el6_8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}
