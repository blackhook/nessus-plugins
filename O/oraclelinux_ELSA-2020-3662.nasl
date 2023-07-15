##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-3662.
##

include('compat.inc');

if (description)
{
  script_id(140482);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-11039",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11045",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11050",
    "CVE-2019-13224",
    "CVE-2019-13225",
    "CVE-2019-16163",
    "CVE-2019-19203",
    "CVE-2019-19204",
    "CVE-2019-19246",
    "CVE-2019-20454",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7064",
    "CVE-2020-7065",
    "CVE-2020-7066"
  );
  script_bugtraq_id(108520, 108525);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 8 : php:7.3 (ELSA-2020-3662)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-3662 advisory.

  - Function iconv_mime_decode_headers() in PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x
    below 7.3.6 may perform out-of-buffer read due to integer overflow when parsing MIME headers. This may
    lead to information disclosure or crash. (CVE-2019-11039)

  - When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below 7.3.6 it is possible to supply it with
    data what will cause it to read past the allocated buffer. This may lead to information disclosure or
    crash. (CVE-2019-11040)

  - When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to supply it with
    data what will cause it to read past the allocated buffer. This may lead to information disclosure or
    crash. (CVE-2019-11041, CVE-2019-11042)

  - When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and 7.4.0 it is possible to supply it with data what
    will cause it to read past the allocated buffer. This may lead to information disclosure or crash.
    (CVE-2019-11047, CVE-2019-11050)

  - In PHP versions 7.2.x below 7.2.31, 7.3.x below 7.3.18 and 7.4.x below 7.4.6, when HTTP file uploads are
    allowed, supplying overly long filenames or field names could lead PHP engine to try to allocate oversized
    memory storage, hit the memory limit and stop processing the request, without cleaning up temporary files
    created by upload request. This potentially could lead to accumulation of uncleaned temporary files
    exhausting the disk space on the target server. (CVE-2019-11048)

  - A NULL Pointer Dereference in match_at() in regexec.c in Oniguruma 6.9.2 allows attackers to potentially
    cause denial of service by providing a crafted regular expression. Oniguruma issues often affect Ruby, as
    well as common optional libraries for PHP and Rust. (CVE-2019-13225)

  - Oniguruma before 6.9.3 allows Stack Exhaustion in regcomp.c because of recursion in regparse.c.
    (CVE-2019-16163)

  - An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function gb18030_mbc_enc_len in file
    gb18030.c, a UChar pointer is dereferenced without checking if it passed the end of the matched string.
    This leads to a heap-based buffer over-read. (CVE-2019-19203)

  - Oniguruma through 6.9.3, as used in PHP 7.3.x and other products, has a heap-based buffer over-read in
    str_lower_case_match in regexec.c. (CVE-2019-19246)

  - An out-of-bounds read was discovered in PCRE before 10.34 when the pattern \X is JIT compiled and used to
    match specially crafted subjects in non-UTF mode. Applications that use PCRE to parse untrusted input may
    be vulnerable to this flaw, which would allow an attacker to crash the application. The flaw occurs in
    do_extuni_no_utf in pcre2_jit_compile.c. (CVE-2019-20454)

  - In PHP versions 7.2.x below 7.2.9, 7.3.x below 7.3.16 and 7.4.x below 7.4.4, while parsing EXIF data with
    exif_read_data() function, it is possible for malicious data to cause PHP to read one byte of
    uninitialized memory. This could potentially lead to information disclosure or crash. (CVE-2020-7064)

  - In PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and 7.4.0, PHP DirectoryIterator class accepts
    filenames with embedded \0 byte and treats them as terminating at that byte. This could lead to security
    vulnerabilities, e.g. in applications checking paths that the code is allowed to access. (CVE-2019-11045)

  - A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2 allows attackers to potentially cause
    information disclosure, denial of service, or possibly code execution by providing a crafted regular
    expression. The attacker provides a pair of a regex pattern and a string, with a multi-byte encoding that
    gets handled by onig_new_deluxe(). Oniguruma issues often affect Ruby, as well as common optional
    libraries for PHP and Rust. (CVE-2019-13224)

  - An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function fetch_interval_quantifier
    (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This
    leads to a heap-based buffer over-read. (CVE-2019-19204)

  - When using fgetss() function to read data with stripping tags, in PHP versions 7.2.x below 7.2.27, 7.3.x
    below 7.3.14 and 7.4.x below 7.4.2 it is possible to supply data that will cause this function to read
    past the allocated buffer. This may lead to information disclosure or crash. (CVE-2020-7059)

  - When using certain mbstring functions to convert multibyte encodings, in PHP versions 7.2.x below 7.2.27,
    7.3.x below 7.3.14 and 7.4.x below 7.4.2 it is possible to supply data that will cause function
    mbfl_filt_conv_big5_wchar to read past the allocated buffer. This may lead to information disclosure or
    crash. (CVE-2020-7060)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below 7.4.3, when using file upload
    functionality, if upload progress tracking is enabled, but session.upload_progress.cleanup is set to 0
    (disabled), and the file upload fails, the upload procedure would try to clean up data that does not exist
    and encounter null pointer dereference, which would likely lead to a crash. (CVE-2020-7062)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below 7.4.3, when creating PHAR archive
    using PharData::buildFromIterator() function, the files are added with default permissions (0666, or all
    access) even if the original files on the filesystem were with more restrictive permissions. This may
    result in files having more lax permissions than intended when such archive is extracted. (CVE-2020-7063)

  - In PHP versions 7.3.x below 7.3.16 and 7.4.x below 7.4.4, while using mb_strtolower() function with
    UTF-32LE encoding, certain invalid strings could cause PHP to overwrite stack-allocated buffer. This could
    lead to memory corruption, crashes and potentially code execution. (CVE-2020-7065)

  - In PHP versions 7.2.x below 7.2.29, 7.3.x below 7.3.16 and 7.4.x below 7.4.4, while using get_headers()
    with user-supplied URL, if the URL contains zero (\0) character, the URL will be silently truncated at it.
    This may cause some software to make incorrect assumptions about the target of the get_headers() and
    possibly send some information to a wrong server. (CVE-2020-7066)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-3662.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13224");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');
if ('7.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

appstreams = {
    'php:7.3': [
      {'reference':'apcu-panel-5.1.17-1.module+el8.2.0+5569+98c8b30d', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.2-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.9-1.module+el8.2.0+5569+98c8b30d', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'php-pecl-apcu-5.1.17-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.17-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.17-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-rrd-2.0.1-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-xdebug-2.8.0-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.4-1.module+el8.2.0+5569+98c8b30d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.4-1.module+el8.2.0+5569+98c8b30d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.3.20-1.module+el8.2.0+7784+4033621d', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-devel / etc');
}
