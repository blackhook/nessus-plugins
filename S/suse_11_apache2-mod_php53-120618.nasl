#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64104);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-2143", "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386");

  script_name(english:"SuSE 11.2 Security Update : PHP5 (SAT Patch Number 6440)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP5 was updated with incremental fixes to the previous update.

  - Additional unsafe cgi wrapper scripts are also fixed
    now. (CVE-2012-2335)

  - Even more commandline option handling is filtered, which
    could lead to crashes of the php interpreter.
    (CVE-2012-2336)

  - heap-based buffer overflow in php's phar extension.
    (CVE-2012-2386)

  - The crypt() implementation ignored wide characters,
    leading to shorter effective password lengths. Note:
    With this update applied affected passwords will no
    longer work and need to be set again. (CVE-2012-2143)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2335.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2336.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2386.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6440.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:apache2-mod_php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:php53-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"apache2-mod_php53-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-bcmath-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-bz2-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-calendar-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-ctype-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-curl-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-dba-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-dom-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-exif-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-fastcgi-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-fileinfo-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-ftp-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-gd-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-gettext-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-gmp-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-iconv-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-intl-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-json-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-ldap-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-mbstring-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-mcrypt-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-mysql-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-odbc-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-openssl-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-pcntl-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-pdo-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-pear-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-pgsql-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-pspell-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-shmop-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-snmp-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-soap-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-suhosin-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-sysvmsg-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-sysvsem-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-sysvshm-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-tokenizer-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-wddx-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-xmlreader-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-xmlrpc-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-xmlwriter-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-xsl-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-zip-5.3.8-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"php53-zlib-5.3.8-0.33.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
