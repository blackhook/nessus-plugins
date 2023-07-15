#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130683);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9767",
    "CVE-2015-6831",
    "CVE-2015-6832",
    "CVE-2015-6833",
    "CVE-2015-8867",
    "CVE-2015-8879",
    "CVE-2015-8935",
    "CVE-2016-10161",
    "CVE-2016-2554",
    "CVE-2016-3141",
    "CVE-2016-3142",
    "CVE-2016-3185",
    "CVE-2016-4070",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4541",
    "CVE-2016-4542",
    "CVE-2016-4543",
    "CVE-2016-5093",
    "CVE-2016-5094",
    "CVE-2016-7124",
    "CVE-2016-7414",
    "CVE-2016-9934",
    "CVE-2016-9935",
    "CVE-2017-11143",
    "CVE-2017-11144",
    "CVE-2017-11147",
    "CVE-2017-12933",
    "CVE-2017-9226"
  );

  script_name(english:"EulerOS 2.0 SP5 : php (EulerOS-SA-2019-2221)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - ext/standard/var_unserializer.c in PHP before 5.6.25
    and 7.x before 7.0.10 mishandles certain invalid
    objects, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via crafted serialized data that leads to a (1)
    __destruct call or (2) magic method
    call.(CVE-2016-7124)

  - Stack-based buffer overflow in ext/phar/tar.c in PHP
    before 5.5.32, 5.6.x before 5.6.18, and 7.x before
    7.0.3 allows remote attackers to cause a denial of
    service (application crash) or possibly have
    unspecified other impact via a crafted TAR
    archive.(CVE-2016-2554)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6831)

  - The sapi_header_op function in main/SAPI.c in PHP
    before 5.4.38, 5.5.x before 5.5.22, and 5.6.x before
    5.6.6 supports deprecated line folding without
    considering browser compatibility, which allows remote
    attackers to conduct cross-site scripting (XSS) attacks
    against Internet Explorer by leveraging (1) %0A%20 or
    (2) %0D%0A%20 mishandling in the header
    function.(CVE-2015-8935)

  - The openssl_random_pseudo_bytes function in
    ext/openssl/openssl.c in PHP before 5.4.44, 5.5.x
    before 5.5.28, and 5.6.x before 5.6.12 incorrectly
    relies on the deprecated RAND_pseudo_bytes function,
    which makes it easier for remote attackers to defeat
    cryptographic protection mechanisms via unspecified
    vectors.(CVE-2015-8867)

  - Use-after-free vulnerability in the SPL unserialize
    implementation in ext/spl/spl_array.c in PHP before
    5.4.44, 5.5.x before 5.5.28, and 5.6.x before 5.6.12
    allows remote attackers to execute arbitrary code via
    crafted serialized data that triggers misuse of an
    array field.(CVE-2015-6832)

  - Directory traversal vulnerability in the PharData class
    in PHP before 5.4.44, 5.5.x before 5.5.28, and 5.6.x
    before 5.6.12 allows remote attackers to write to
    arbitrary files via a .. (dot dot) in a ZIP archive
    entry that is mishandled during an extractTo
    call.(CVE-2015-6833)

  - Directory traversal vulnerability in the
    ZipArchive::extractTo function in ext/zip/php_zip.c in
    PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x
    before 5.6.13 and ext/zip/ext_zip.cpp in HHVM before
    3.12.1 allows remote attackers to create arbitrary
    empty directories via a crafted ZIP
    archive.(CVE-2014-9767)

  - The ZIP signature-verification feature in PHP before
    5.6.26 and 7.x before 7.0.11 does not ensure that the
    uncompressed_filesize field is large enough, which
    allows remote attackers to cause a denial of service
    (out-of-bounds memory access) or possibly have
    unspecified other impact via a crafted PHAR archive,
    related to ext/phar/util.c and
    ext/phar/zip.c.(CVE-2016-7414)

  - ext/wddx/wddx.c in PHP before 5.6.28 and 7.x before
    7.0.13 allows remote attackers to cause a denial of
    service (NULL pointer dereference) via crafted
    serialized data in a wddxPacket XML document, as
    demonstrated by a PDORow string.(CVE-2016-9934)

  - The php_wddx_push_element function in ext/wddx/wddx.c
    in PHP before 5.6.29 and 7.x before 7.0.14 allows
    remote attackers to cause a denial of service
    (out-of-bounds read and memory corruption) or possibly
    have unspecified other impact via an empty boolean
    element in a wddxPacket XML document.(CVE-2016-9935)

  - In PHP before 5.6.31, an invalid free in the WDDX
    deserialization of boolean parameters could be used by
    attackers able to inject XML for deserialization to
    crash the PHP interpreter, related to an invalid free
    for an empty boolean element in
    ext/wddx/wddx.c.(CVE-2017-11143)

  - Integer overflow in the php_html_entities function in
    ext/standard/html.c in PHP before 5.5.36 and 5.6.x
    before 5.6.22 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact by
    triggering a large output string from the
    htmlspecialchars function.(CVE-2016-5094)

  - The get_icu_value_internal function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.36,
    5.6.x before 5.6.22, and 7.x before 7.0.7 does not
    ensure the presence of a '\0' character, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a crafted locale_get_primary_language
    call.(CVE-2016-5093)

  - The grapheme_strpos function in
    ext/intl/grapheme/grapheme_string.c in PHP before
    5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset.(CVE-2016-4541)

  - The exif_process_IFD_TAG function in ext/exif/exif.c in
    PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 does not properly construct spprintf arguments,
    which allows remote attackers to cause a denial of
    service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header
    data.(CVE-2016-4542)

  - The phar_parse_zipfile function in zip.c in the PHAR
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service
    (out-of-bounds read and application crash) by placing a
    PK\x05\x06 signature at an invalid
    location.(CVE-2016-3142)

  - ** DISPUTED ** Integer overflow in the
    php_raw_url_encode function in ext/standard/url.c in
    PHP before 5.5.34, 5.6.x before 5.6.20, and 7.x before
    7.0.5 allows remote attackers to cause a denial of
    service (application crash) via a long string to the
    rawurlencode function. NOTE: the vendor says 'Not sure
    if this qualifies as security issue (probably
    not).'(CVE-2016-4070)

  - The xml_parse_into_struct function in ext/xml/xml.c in
    PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 allows remote attackers to cause a denial of
    service (buffer under-read and segmentation fault) or
    possibly have unspecified other impact via crafted XML
    data in the second argument, leading to a parser level
    of zero.(CVE-2016-4539)

  - The grapheme_stripos function in
    ext/intl/grapheme/grapheme_string.c in PHP before
    5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset.(CVE-2016-4540)

  - Use-after-free vulnerability in wddx.c in the WDDX
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact by triggering a
    wddx_deserialize call on XML data containing a crafted
    var element.(CVE-2016-3141)

  - In PHP before 5.6.30 and 7.x before 7.0.15, the PHAR
    archive handler could be used by attackers supplying
    malicious archive files to crash the PHP interpreter or
    potentially disclose information due to a buffer
    over-read in the phar_parse_pharfile function in
    ext/phar/phar.c.(CVE-2017-11147)

  - The exif_process_IFD_in_JPEG function in
    ext/exif/exif.c in PHP before 5.5.35, 5.6.x before
    5.6.21, and 7.x before 7.0.6 does not validate IFD
    sizes, which allows remote attackers to cause a denial
    of service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header
    data.(CVE-2016-4543)

  - The odbc_bindcols function in ext/odbc/php_odbc.c in
    PHP before 5.6.12 mishandles driver behavior for
    SQL_WVARCHAR columns, which allows remote attackers to
    cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table.(CVE-2015-8879)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A heap out-of-bounds write or read
    occurs in next_state_val() during regular expression
    compilation. Octal numbers larger than 0xff are not
    handled correctly in fetch_token() and
    fetch_token_in_cc(). A malformed regular expression
    containing an octal number in the form of '\700' would
    produce an invalid code point value larger than 0xff in
    next_state_val(), resulting in an out-of-bounds write
    memory corruption.(CVE-2017-9226)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, the openssl extension PEM sealing code
    did not check the return value of the OpenSSL sealing
    function, which could lead to a crash of the PHP
    interpreter, related to an interpretation conflict for
    a negative number in ext/openssl/openssl.c, and an
    OpenSSL documentation omission.(CVE-2017-11144)

  - The make_http_soap_request function in
    ext/soap/php_http.c in PHP before 5.4.44, 5.5.x before
    5.5.28, 5.6.x before 5.6.12, and 7.x before 7.0.4
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service (type
    confusion and application crash) via crafted serialized
    _cookies data, related to the SoapClient::__call method
    in ext/soap/soap.c.(CVE-2016-3185)

  - The object_common1 function in
    ext/standard/var_unserializer.c in PHP before 5.6.30,
    7.0.x before 7.0.15, and 7.1.x before 7.1.1 allows
    remote attackers to cause a denial of service (buffer
    over-read and application crash) via crafted serialized
    data that is mishandled in a finish_nested_data
    call.(CVE-2016-10161)

  - The finish_nested_data function in
    ext/standard/var_unserializer.re in PHP before 5.6.31,
    7.0.x before 7.0.21, and 7.1.x before 7.1.7 is prone to
    a buffer over-read while unserializing untrusted data.
    Exploitation of this issue can have an unspecified
    impact on the integrity of PHP.(CVE-2017-12933)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce72047f");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h19.eulerosv2r7",
        "php-cli-5.4.16-45.h19.eulerosv2r7",
        "php-common-5.4.16-45.h19.eulerosv2r7",
        "php-gd-5.4.16-45.h19.eulerosv2r7",
        "php-ldap-5.4.16-45.h19.eulerosv2r7",
        "php-mysql-5.4.16-45.h19.eulerosv2r7",
        "php-odbc-5.4.16-45.h19.eulerosv2r7",
        "php-pdo-5.4.16-45.h19.eulerosv2r7",
        "php-pgsql-5.4.16-45.h19.eulerosv2r7",
        "php-process-5.4.16-45.h19.eulerosv2r7",
        "php-recode-5.4.16-45.h19.eulerosv2r7",
        "php-soap-5.4.16-45.h19.eulerosv2r7",
        "php-xml-5.4.16-45.h19.eulerosv2r7",
        "php-xmlrpc-5.4.16-45.h19.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
