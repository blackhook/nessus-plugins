#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142352);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-4071",
    "CVE-2016-4072",
    "CVE-2016-4073",
    "CVE-2016-5772",
    "CVE-2017-11362",
    "CVE-2017-9118",
    "CVE-2019-11036",
    "CVE-2019-11039",
    "CVE-2019-11045",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11050",
    "CVE-2019-13224",
    "CVE-2019-19246",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7062",
    "CVE-2020-7063"
  );

  script_name(english:"EulerOS 2.0 SP2 : php (EulerOS-SA-2020-2384)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A use-after-free in onig_new_deluxe() in regext.c in
    Oniguruma 6.9.2 allows attackers to potentially cause
    information disclosure, denial of service, or possibly
    code execution by providing a crafted regular
    expression. The attacker provides a pair of a regex
    pattern and a string, with a multi-byte encoding that
    gets handled by onig_new_deluxe(). Oniguruma issues
    often affect Ruby, as well as common optional libraries
    for PHP and Rust.(CVE-2019-13224)

  - PHP 7.1.5 has an Out of bounds access in
    php_pcre_replace_impl via a crafted preg_replace
    call.(CVE-2017-9118)

  - Double free vulnerability in the php_wddx_process_data
    function in wddx.c in the WDDX extension in PHP before
    5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8
    allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via crafted XML data that is mishandled in a
    wddx_deserialize call.(CVE-2016-5772)

  - When using fgetss() function to read data with
    stripping tags, in PHP versions 7.2.x below 7.2.27,
    7.3.x below 7.3.14 and 7.4.x below 7.4.2 it is possible
    to supply data that will cause this function to read
    past the allocated buffer. This may lead to information
    disclosure or crash.(CVE-2020-7059)

  - When using certain mbstring functions to convert
    multibyte encodings, in PHP versions 7.2.x below
    7.2.27, 7.3.x below 7.3.14 and 7.4.x below 7.4.2 it is
    possible to supply data that will cause function
    mbfl_filt_conv_big5_wchar to read past the allocated
    buffer. This may lead to information disclosure or
    crash.(CVE-2020-7060)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15
    and 7.4.x below 7.4.3, when using file upload
    functionality, if upload progress tracking is enabled,
    but session.upload_progress.cleanup is set to 0
    (disabled), and the file upload fails, the upload
    procedure would try to clean up data that does not
    exist and encounter null pointer dereference, which
    would likely lead to a crash.(CVE-2020-7062)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15
    and 7.4.x below 7.4.3, when creating PHAR archive using
    PharData::buildFromIterator() function, the files are
    added with default permissions (0666, or all access)
    even if the original files on the filesystem were with
    more restrictive permissions. This may result in files
    having more lax permissions than intended when such
    archive is extracted.(CVE-2020-7063)

  - Format string vulnerability in the php_snmp_error
    function in ext/snmp/snmp.c in PHP before 5.5.34, 5.6.x
    before 5.6.20, and 7.x before 7.0.5 allows remote
    attackers to execute arbitrary code via format string
    specifiers in an SNMP::get call.(CVE-2016-4071)

  - The Phar extension in PHP before 5.5.34, 5.6.x before
    5.6.20, and 7.x before 7.0.5 allows remote attackers to
    execute arbitrary code via a crafted filename, as
    demonstrated by mishandling of \0 characters by the
    phar_analyze_path function in
    ext/phar/phar.c.(CVE-2016-4072)

  - Multiple integer overflows in the mbfl_strcut function
    in ext/mbstring/libmbfl/mbfl/mbfilter.c in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allow
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted mb_strcut call.(CVE-2016-4073)

  - In PHP 7.x before 7.0.21 and 7.1.x before 7.1.7,
    ext/intl/msgformat/msgformat_parse.c does not restrict
    the locale length, which allows remote attackers to
    cause a denial of service (stack-based buffer overflow
    and application crash) or possibly have unspecified
    other impact within International Components for
    Unicode (ICU) for C/C++ via a long first argument to
    the msgfmt_parse_message function.(CVE-2017-11362)

  - When processing certain files, PHP EXIF extension in
    versions 7.1.x below 7.1.29, 7.2.x below 7.2.18 and
    7.3.x below 7.3.5 can be caused to read past allocated
    buffer in exif_process_IFD_TAG function. This may lead
    to information disclosure or crash.(CVE-2019-11036)

  - Function iconv_mime_decode_headers() in PHP versions
    7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below
    7.3.6 may perform out-of-buffer read due to integer
    overflow when parsing MIME headers. This may lead to
    information disclosure or crash.(CVE-2019-11039)

  - In PHP versions 7.2.x below 7.2.31, 7.3.x below 7.3.18
    and 7.4.x below 7.4.6, when HTTP file uploads are
    allowed, supplying overly long filenames or field names
    could lead PHP engine to try to allocate oversized
    memory storage, hit the memory limit and stop
    processing the request, without cleaning up temporary
    files created by upload request. This potentially could
    lead to accumulation of uncleaned temporary files
    exhausting the disk space on the target
    server.(CVE-2019-11048)

  - In PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13
    and 7.4.0, PHP DirectoryIterator class accepts
    filenames with embedded \0 byte and treats them as
    terminating at that byte. This could lead to security
    vulnerabilities, e.g. in applications checking paths
    that the code is allowed to access.(CVE-2019-11045)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and
    7.4.0 it is possible to supply it with data what will
    cause it to read past the allocated buffer. This may
    lead to information disclosure or
    crash.(CVE-2019-11047)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and
    7.4.0 it is possible to supply it with data what will
    cause it to read past the allocated buffer. This may
    lead to information disclosure or
    crash.(CVE-2019-11050)

  - Oniguruma through 6.9.3, as used in PHP 7.3.x and other
    products, has a heap-based buffer over-read in
    str_lower_case_match in regexec.c.(CVE-2019-19246)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ec52fe0");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-42.h70",
        "php-cli-5.4.16-42.h70",
        "php-common-5.4.16-42.h70",
        "php-gd-5.4.16-42.h70",
        "php-ldap-5.4.16-42.h70",
        "php-mysql-5.4.16-42.h70",
        "php-odbc-5.4.16-42.h70",
        "php-pdo-5.4.16-42.h70",
        "php-pgsql-5.4.16-42.h70",
        "php-process-5.4.16-42.h70",
        "php-recode-5.4.16-42.h70",
        "php-soap-5.4.16-42.h70",
        "php-xml-5.4.16-42.h70",
        "php-xmlrpc-5.4.16-42.h70"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
