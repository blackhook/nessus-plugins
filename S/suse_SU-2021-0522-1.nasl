#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0522-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(146669);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id("CVE-2021-21702");

  script_name(english:"SUSE SLES12 Security Update : php74 (SUSE-SU-2021:0522-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for php74 fixes the following issues :

CVE-2021-21702 [bsc#1182049]: NULL pointer dereference in SoapClient

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-21702/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210522-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb4ba79a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-522=1

SUSE Linux Enterprise Module for Web Scripting 12 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-12-2021-522=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php74-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sodium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php74-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php74-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-bcmath-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-bcmath-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-bz2-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-bz2-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-calendar-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-calendar-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ctype-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ctype-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-curl-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-curl-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-dba-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-dba-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-debugsource-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-dom-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-dom-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-enchant-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-enchant-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-exif-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-exif-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fastcgi-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fastcgi-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fileinfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fileinfo-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fpm-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-fpm-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ftp-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ftp-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gd-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gd-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gettext-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gettext-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gmp-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-gmp-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-iconv-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-iconv-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-intl-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-intl-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-json-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-json-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ldap-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-ldap-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-mbstring-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-mbstring-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-mysql-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-mysql-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-odbc-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-odbc-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-opcache-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-opcache-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-openssl-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-openssl-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pcntl-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pcntl-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pdo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pdo-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pgsql-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-pgsql-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-phar-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-phar-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-posix-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-posix-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-readline-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-readline-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-shmop-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-shmop-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-snmp-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-snmp-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-soap-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-soap-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sockets-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sockets-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sodium-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sodium-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sqlite-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sqlite-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvmsg-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvmsg-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvsem-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvsem-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvshm-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-sysvshm-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-tidy-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-tidy-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-tokenizer-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-tokenizer-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlreader-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlreader-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlrpc-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlrpc-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlwriter-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xmlwriter-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xsl-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-xsl-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-zip-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-zip-debuginfo-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-zlib-7.4.6-1.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php74-zlib-debuginfo-7.4.6-1.19.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php74");
}
