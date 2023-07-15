#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2522-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103317);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10168", "CVE-2016-10397", "CVE-2016-5766", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11146", "CVE-2017-11147", "CVE-2017-11628", "CVE-2017-12933", "CVE-2017-7890");

  script_name(english:"SUSE SLES11 Security Update : php53 (SUSE-SU-2017:2522-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php53 fixes the several issues. These security issues
were fixed :

  - CVE-2017-12933: The finish_nested_data function in
    ext/standard/var_unserializer.re was prone to a buffer
    over-read while unserializing untrusted data.
    Exploitation of this issue could have had an unspecified
    impact on the integrity of PHP (bsc#1054430).

  - CVE-2017-11628: Stack-based buffer overflow in the
    zend_ini_do_op() function in Zend/zend_ini_parser.c
    could have caused a denial of service or potentially
    allowed executing code (bsc#1050726).

  - CVE-2017-7890: The GIF decoding function
    gdImageCreateFromGifCtx in the GD Graphics Library did
    not zero colorMap arrays use. A specially crafted GIF
    image could use the uninitialized tables to read ~700
    bytes from the top of the stack, potentially disclosing
    sensitive information (bsc#1050241).

  - CVE-2016-5766: Integer overflow in the _gd2GetHeader in
    the GD Graphics Library (aka libgd) allowed remote
    attackers to cause a denial of service (heap-based
    buffer overflow and application crash) or possibly have
    unspecified other impact via crafted chunk dimensions in
    an image (bsc#986386).

  - CVE-2017-11145: An error in the date extension's
    timelib_meridian parsing code could have been used by
    attackers able to supply date strings to leak
    information from the interpreter, related to
    ext/date/lib/parse_date.c out-of-bounds reads affecting
    the php_parse_date function (bsc#1048112).

  - CVE-2017-11146: Lack of bounds checks in
    timelib_meridian parse code could have lead to
    information leak [bsc#1048111]

  - CVE-2016-10397: Incorrect handling of various URI
    components in the URL parser could have been used by
    attackers to bypass hostname-specific URL checks
    (bsc#1047454).

  - CVE-2017-11147: The PHAR archive handler could have been
    used by attackers supplying malicious archive files to
    crash the PHP interpreter or potentially disclose
    information due to a buffer over-read in the
    phar_parse_pharfile function (bsc#1048094).

  - CVE-2017-11144: The openssl extension PEM sealing code
    did not check the return value of the OpenSSL sealing
    function, which could have lead to a crash of the PHP
    interpreter (bsc#1048096).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10168/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10397/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5766/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11144/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11145/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11146/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11147/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11628/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12933/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7890/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172522-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf3f2ab3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-php53-13282=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-php53-13282=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-php53-13282=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"apache2-mod_php53-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bcmath-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-bz2-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-calendar-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ctype-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-curl-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dba-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-dom-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-exif-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fastcgi-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-fileinfo-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ftp-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gd-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gettext-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-gmp-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-iconv-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-intl-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-json-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-ldap-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mbstring-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mcrypt-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-mysql-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-odbc-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-openssl-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pcntl-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pdo-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pear-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pgsql-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-pspell-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-shmop-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-snmp-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-soap-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-suhosin-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvmsg-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvsem-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-sysvshm-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-tokenizer-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-wddx-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlreader-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlrpc-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xmlwriter-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-xsl-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zip-5.3.17-112.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"php53-zlib-5.3.17-112.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53");
}
