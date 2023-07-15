#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1633-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93160);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-7456", "CVE-2015-8876", "CVE-2015-8877", "CVE-2015-8879", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : php5 (SUSE-SU-2016:1633-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php5 fixes the following issues :

  - CVE-2013-7456: imagescale out-of-bounds read
    (bnc#982009).

  - CVE-2016-5093: get_icu_value_internal out-of-bounds read
    (bnc#982010).

  - CVE-2016-5094: Don't create strings with lengths outside
    of valid range (bnc#982011).

  - CVE-2016-5095: Don't create strings with lengths outside
    of valid range (bnc#982012).

  - CVE-2016-5096: int/size_t confusion in fread
    (bsc#982013).

  - CVE-2015-8877: The gdImageScaleTwoPass function in
    gd_interpolation.c in the GD Graphics Library (aka
    libgd) as used in PHP used inconsistent allocate and
    free approaches, which allowed remote attackers to cause
    a denial of service (memory consumption) via a crafted
    call, as demonstrated by a call to the PHP imagescale
    function (bsc#981061).

  - CVE-2015-8876: Zend/zend_exceptions.c in PHP did not
    validate certain Exception objects, which allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) or trigger unintended
    method execution via crafted serialized data
    (bsc#981049).

  - CVE-2015-8879: The odbc_bindcols function in
    ext/odbc/php_odbc.c in PHP mishandles driver behavior
    for SQL_WVARCHAR columns, which allowed remote attackers
    to cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table (bsc#981050).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8876/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8877/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8879/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5093/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5094/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5095/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5096/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161633-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c69169d7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-968=1

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-968=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-968=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-968=1

SUSE Linux Enterprise Module for Web Scripting 12 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-12-2016-968=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-968=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-968=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:imap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libc-client2007e_suse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libc-client2007e_suse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libc-client2007e_suse-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libc-client2007e_suse-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debugsource-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-debuginfo-5.5.14-64.5")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"imap-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"imap-debugsource-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libc-client2007e_suse-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libc-client2007e_suse-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"imap-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"imap-debugsource-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libc-client2007e_suse-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libc-client2007e_suse-debuginfo-2007e_suse-19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
