#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1344.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(130470);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"ALAS", value:"2019-1344");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"Amazon Linux 2 : php (ALAS-2019-1344)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below
7.3.11 in certain configurations of FPM setup it is possible to cause
FPM module to write past allocated buffers into the space reserved for
FCGI protocol data, thus opening the possibility of remote code
execution.(CVE-2019-11043)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1344.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update php' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"php-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-bcmath-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-cli-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-common-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-dba-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-debuginfo-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-devel-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-embedded-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-enchant-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-fpm-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-gd-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-intl-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-ldap-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-mbstring-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-mysqlnd-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-odbc-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-pdo-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-pgsql-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-process-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-pspell-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-recode-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-snmp-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-soap-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-xml-5.4.16-46.amzn2.0.2")) flag++;
if (rpm_check(release:"AL2", reference:"php-xmlrpc-5.4.16-46.amzn2.0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
