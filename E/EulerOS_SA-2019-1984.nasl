#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129178);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9912",
    "CVE-2015-4116",
    "CVE-2015-7803",
    "CVE-2015-7804",
    "CVE-2015-8866",
    "CVE-2015-8874",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-6288",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6294",
    "CVE-2016-7125",
    "CVE-2016-7128",
    "CVE-2016-7418",
    "CVE-2017-11628",
    "CVE-2018-10545",
    "CVE-2018-10547",
    "CVE-2018-14851",
    "CVE-2018-17082",
    "CVE-2018-5711",
    "CVE-2018-5712"
  );

  script_name(english:"EulerOS 2.0 SP5 : php (EulerOS-SA-2019-1984)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - The get_icu_disp_value_src_php function in
    ext/intl/locale/locale_methods.c in PHP before 5.3.29,
    5.4.x before 5.4.30, and 5.5.x before 5.5.14 does not
    properly restrict calls to the ICU uresbund.cpp
    component, which allows remote attackers to cause a
    denial of service (buffer overflow) or possibly have
    unspecified other impact via a locale_get_display_name
    call with a long first argument.(CVE-2014-9912)

  - Use-after-free vulnerability in the spl_ptr_heap_insert
    function in ext/spl/spl_heap.c in PHP before 5.5.27 and
    5.6.x before 5.6.11 allows remote attackers to execute
    arbitrary code by triggering a failed
    SplMinHeap::compare operation.(CVE-2015-4116)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-7803)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-7804)

  - ext/libxml/libxml.c in PHP before 5.5.22 and 5.6.x
    before 5.6.6, when PHP-FPM is used, does not isolate
    each thread from libxml_disable_entity_loader changes
    in other threads, which allows remote attackers to
    conduct XML External Entity (XXE) and XML Entity
    Expansion (XEE) attacks via a crafted XML document, a
    related issue to CVE-2015-5161.(CVE-2015-8866)

  - Stack consumption vulnerability in GD in PHP before
    5.6.12 allows remote attackers to cause a denial of
    service via a crafted imagefilltoborder
    call.(CVE-2015-8874)

  - It was found that the exif_convert_any_to_int()
    function in PHP was vulnerable to floating point
    exceptions when parsing tags in image files. A remote
    attacker with the ability to upload a malicious image
    could crash PHP, causing a Denial of
    Service.(CVE-2016-10158)

  - Integer overflow in the phar_parse_pharfile function in
    ext/phar/phar.c in PHP before 5.6.30 and 7.0.x before
    7.0.15 allows remote attackers to cause a denial of
    service (memory consumption or application crash) via a
    truncated manifest entry in a PHAR
    archive.(CVE-2016-10159)

  - The php_url_parse_ex function in ext/standard/url.c in
    PHP before 5.5.38 allows remote attackers to cause a
    denial of service (buffer over-read) or possibly have
    unspecified other impact via vectors involving the
    smart_str data type.(CVE-2016-6288)

  - The exif_process_IFD_in_MAKERNOTE function in
    ext/exif/exif.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 allows remote attackers to
    cause a denial of service (out-of-bounds array access
    and memory corruption), obtain sensitive information
    from process memory, or possibly have unspecified other
    impact via a crafted JPEG image.(CVE-2016-6291)

  - The exif_process_user_comment function in
    ext/exif/exif.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) via a crafted JPEG
    image.(CVE-2016-6292)

  - The locale_accept_from_http function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.38,
    5.6.x before 5.6.24, and 7.x before 7.0.9 does not
    properly restrict calls to the ICU
    uloc_acceptLanguageFromHTTP function, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a call with a long argument.(CVE-2016-6294)

  - ext/session/session.c in PHP before 5.6.25 and 7.x
    before 7.0.10 skips invalid session names in a way that
    triggers incorrect parsing, which allows remote
    attackers to inject arbitrary-type session data by
    leveraging control of a session name, as demonstrated
    by object injection.(CVE-2016-7125)

  - The exif_process_IFD_in_TIFF function in
    ext/exif/exif.c in PHP before 5.6.25 and 7.x before
    7.0.10 mishandles the case of a thumbnail offset that
    exceeds the file size, which allows remote attackers to
    obtain sensitive information from process memory via a
    crafted TIFF image.(CVE-2016-7128)

  - The php_wddx_push_element function in ext/wddx/wddx.c
    in PHP before 5.6.26 and 7.x before 7.0.11 allows
    remote attackers to cause a denial of service (invalid
    pointer access and out-of-bounds read) or possibly have
    unspecified other impact via an incorrect boolean
    element in a wddxPacket XML document, leading to
    mishandling in a wddx_deserialize call.(CVE-2016-7418)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, a stack-based buffer overflow in the
    zend_ini_do_op() function in Zend/zend_ini_parser.c
    could cause a denial of service or potentially allow
    executing code. NOTE: this is only relevant for PHP
    applications that accept untrusted input (instead of
    the system's php.ini file) for the parse_ini_string or
    parse_ini_file function, e.g., a web application for
    syntax validation of php.ini
    directives.(CVE-2017-11628)

  - An issue was discovered in PHP before 5.6.35, 7.0.x
    before 7.0.29, 7.1.x before 7.1.16, and 7.2.x before
    7.2.4. Dumpable FPM child processes allow bypassing
    opcache access controls because fpm_unix.c makes a
    PR_SET_DUMPABLE prctl call, allowing one user (in a
    multiuser environment) to obtain sensitive information
    from the process memory of a second user's PHP
    applications by running gcore on the PID of the PHP-FPM
    worker process.(CVE-2018-10545)

  - An issue was discovered in ext/phar/phar_object.c in
    PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before
    7.1.17, and 7.2.x before 7.2.5. There is Reflected XSS
    on the PHAR 403 and 404 error pages via request data of
    a request for a .phar file.(CVE-2018-10547)

  - exif_process_IFD_in_MAKERNOTE in ext/exif/exif.c in PHP
    before 5.6.37, 7.0.x before 7.0.31, 7.1.x before
    7.1.20, and 7.2.x before 7.2.8 allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted JPEG
    file.(CVE-2018-14851)

  - A cross-site scripting (XSS) vulnerability in Apache2
    component of PHP was found. When using
    'Transfer-Encoding: chunked', the request allows remote
    attackers to potentially run a malicious script in a
    victim's browser. This vulnerability can be exploited
    only by producing malformed requests and it's believed
    it's unlikely to be used in practical cross-site
    scripting attack.(CVE-2018-17082)

  - gd_gif_in.c in the GD Graphics Library (aka libgd), as
    used in PHP before 5.6.33, 7.0.x before 7.0.27, 7.1.x
    before 7.1.13, and 7.2.x before 7.2.1, has an integer
    signedness error that leads to an infinite loop via a
    crafted GIF file, as demonstrated by a call to the
    imagecreatefromgif or imagecreatefromstring PHP
    function. This is related to GetCode_ and
    gdImageCreateFromGifCtx.(CVE-2018-5711)

  - An issue was discovered in PHP before 5.6.33, 7.0.x
    before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before
    7.2.1. There is Reflected XSS on the PHAR 404 error
    page via the URI of a request for a .phar
    file.(CVE-2018-5712)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1984
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa8a4c3f");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

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

pkgs = ["php-5.4.16-45.h15.eulerosv2r7",
        "php-cli-5.4.16-45.h15.eulerosv2r7",
        "php-common-5.4.16-45.h15.eulerosv2r7",
        "php-gd-5.4.16-45.h15.eulerosv2r7",
        "php-ldap-5.4.16-45.h15.eulerosv2r7",
        "php-mysql-5.4.16-45.h15.eulerosv2r7",
        "php-odbc-5.4.16-45.h15.eulerosv2r7",
        "php-pdo-5.4.16-45.h15.eulerosv2r7",
        "php-pgsql-5.4.16-45.h15.eulerosv2r7",
        "php-process-5.4.16-45.h15.eulerosv2r7",
        "php-recode-5.4.16-45.h15.eulerosv2r7",
        "php-soap-5.4.16-45.h15.eulerosv2r7",
        "php-xml-5.4.16-45.h15.eulerosv2r7",
        "php-xmlrpc-5.4.16-45.h15.eulerosv2r7"];

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
