#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136245);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2016-10397",
    "CVE-2016-7412",
    "CVE-2017-11145",
    "CVE-2017-16642",
    "CVE-2017-7189",
    "CVE-2017-7272",
    "CVE-2019-11047",
    "CVE-2019-11050",
    "CVE-2019-19204",
    "CVE-2019-19246"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : php (EulerOS-SA-2020-1542)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - PHP is an HTML-embedded scripting language. PHP
    attempts to make it easy for developers to write
    dynamically generated web pages. PHP also offers
    built-in database integration for several commercial
    and non-commercial database management systems, so
    writing a database-enabled webpage with PHP is fairly
    simple. The most common use of PHP coding is probably
    as a replacement for CGI scripts. The php package
    contains the module (often referred to as mod_php)
    which adds support for the PHP language to Apache HTTP
    Server. Security Fix(es):A flaw was found in HAProxy
    before 2.0.6. In legacy mode, messages featuring a
    transfer-encoding header missing the 'chunked' value
    were not being correctly rejected. The impact was
    limited but if combined with the 'http-reuse always'
    setting, it could be used to help construct an HTTP
    request smuggling attack against a vulnerable component
    employing a lenient parser that would ignore the
    content-length header as soon as it saw a
    transfer-encoding one (even if not entirely valid
    according to the specification).(CVE-2017-16642)In PHP
    before 5.6.32, 7.x before 7.0.25, and 7.1.x before
    7.1.11, an error in the date extension's
    timelib_meridian handling of 'front of' and 'back of'
    directives could be used by attackers able to supply
    date strings to leak information from the interpreter,
    related to ext/date/lib/parse_date.c out-of-bounds
    reads affecting the php_parse_date function. NOTE: this
    is a different issue than
    CVE-2017-11145.(CVE-2017-11145)ext/standard/var_unseria
    lizer.re in PHP before 5.6.26 mishandles
    object-deserialization failures, which allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via an unserialize call that references a partially
    constructed object.(CVE-2016-10397)Double free
    vulnerability in the zend_ts_hash_graceful_destroy
    function in zend_ts_hash.c in the Zend Engine in PHP
    through 5.5.20 and 5.6.x through 5.6.4 allows remote
    attackers to cause a denial of service or possibly have
    unspecified other impact via unknown
    vectors.(CVE-2016-7412)Oniguruma through 6.9.3, as used
    in PHP 7.3.x and other products, has a heap-based
    buffer over-read in str_lower_case_match in
    regexec.c.(CVE-2019-19246)When PHP EXIF extension is
    parsing EXIF information from an image, e.g. via
    exif_read_data() function, in PHP versions 7.2.x below
    7.2.26, 7.3.x below 7.3.13 and 7.4.0 it is possible to
    supply it with data what will cause it to read past the
    allocated buffer. This may lead to information
    disclosure or
    crash.(CVE-2019-11047)main/php_open_temporary_file.c in
    PHP before 5.5.28 and 5.6.x before 5.6.12 does not
    ensure thread safety, which allows remote attackers to
    cause a denial of service (race condition and heap
    memory corruption) by leveraging an application that
    performs many temporary-file
    accesses.(CVE-2017-7272)When PHP EXIF extension is
    parsing EXIF information from an image, e.g. via
    exif_read_data() function, in PHP versions 7.2.x below
    7.2.26, 7.3.x below 7.3.13 and 7.4.0 it is possible to
    supply it with data what will cause it to read past the
    allocated buffer. This may lead to information
    disclosure or crash.(CVE-2019-11050)An issue was
    discovered in Oniguruma 6.x before 6.9.4_rc2. In the
    function fetch_interval_quantifier (formerly known as
    fetch_range_quantifier) in regparse.c, PFETCH is called
    without checking PEND. This leads to a heap-based
    buffer
    over-read.(CVE-2019-19204)main/streams/xp_socket.c in
    PHP 7.x before 2017-03-07 misparses fsockopen calls,
    such as by interpreting fsockopen('127.0.0.1:80', 443)
    as if the address/port were 127.0.0.1:80:443, which is
    later truncated to 127.0.0.1:80. This behavior has a
    security risk if the explicitly provided port number
    (i.e., 443 in this example) is hardcoded into an
    application as a security policy, but the hostname
    argument (i.e., 127.0.0.1:80 in this example) is
    obtained from untrusted input.(CVE-2017-7189)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1542
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97a5d21b");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h29",
        "php-cli-5.4.16-45.h29",
        "php-common-5.4.16-45.h29"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
