#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133925);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-10397",
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2017-11145",
    "CVE-2017-16642",
    "CVE-2017-7272",
    "CVE-2019-11045",
    "CVE-2019-11047",
    "CVE-2019-19246"
  );

  script_name(english:"EulerOS 2.0 SP5 : php (EulerOS-SA-2020-1124)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26
    and 7.x before 7.0.11 does not verify that a BIT field
    has the UNSIGNED_FLAG flag, which allows remote MySQL
    servers to cause a denial of service (heap-based buffer
    overflow) or possibly have unspecified other impact via
    crafted field metadata.(CVE-2016-7412)

  - ext/standard/var_unserializer.re in PHP before 5.6.26
    mishandles object-deserialization failures, which
    allows remote attackers to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via an unserialize call that references a
    partially constructed object.(CVE-2016-7411)

  - In PHP before 5.6.28 and 7.x before 7.0.13, incorrect
    handling of various URI components in the URL parser
    could be used by attackers to bypass hostname-specific
    URL checks, as demonstrated by
    evil.example.com:80#@good.example.com/ and
    evil.example.com:80?@good.example.com/ inputs to the
    parse_url function (implemented in the php_url_parse_ex
    function in ext/standard/url.c).(CVE-2016-10397)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, an error in the date extension's
    timelib_meridian parsing code could be used by
    attackers able to supply date strings to leak
    information from the interpreter, related to
    ext/date/lib/parse_date.c out-of-bounds reads affecting
    the php_parse_date function. NOTE: the correct fix is
    in the e8b7698f5ee757ce2c8bd10a192a491a498f891c commit,
    not the bd77ac90d3bdf31ce2a5251ad92e9e75
    gist.(CVE-2017-11145)

  - In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x
    before 7.1.11, an error in the date extension's
    timelib_meridian handling of 'front of' and 'back of'
    directives could be used by attackers able to supply
    date strings to leak information from the interpreter,
    related to ext/date/lib/parse_date.c out-of-bounds
    reads affecting the php_parse_date function. NOTE: this
    is a different issue than
    CVE-2017-11145.(CVE-2017-16642)

  - In PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13
    and 7.4.0, PHP DirectoryIterator class accepts
    filenames with embedded \0 byte and treats them as
    terminating at that byte. This could lead to security
    vulnerabilities, e.g. in applications checking paths
    that the code is allowed to access.(CVE-2019-11045)

  - Oniguruma through 6.9.3, as used in PHP 7.3.x and other
    products, has a heap-based buffer over-read in
    str_lower_case_match in regexec.c.(CVE-2019-19246)

  - PHP through 7.1.11 enables potential SSRF in
    applications that accept an fsockopen or pfsockopen
    hostname argument with an expectation that the port
    number is constrained. Because a :port syntax is
    recognized, fsockopen will use the port number that is
    specified in the hostname argument, instead of the port
    number in the second argument of the
    function.(CVE-2017-7272)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and
    7.4.0 it is possible to supply it with data what will
    cause it to read past the allocated buffer. This may
    lead to information disclosure or
    crash.(CVE-2019-11047)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f56d33ce");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h27.eulerosv2r7",
        "php-cli-5.4.16-45.h27.eulerosv2r7",
        "php-common-5.4.16-45.h27.eulerosv2r7",
        "php-gd-5.4.16-45.h27.eulerosv2r7",
        "php-ldap-5.4.16-45.h27.eulerosv2r7",
        "php-mysql-5.4.16-45.h27.eulerosv2r7",
        "php-odbc-5.4.16-45.h27.eulerosv2r7",
        "php-pdo-5.4.16-45.h27.eulerosv2r7",
        "php-pgsql-5.4.16-45.h27.eulerosv2r7",
        "php-process-5.4.16-45.h27.eulerosv2r7",
        "php-recode-5.4.16-45.h27.eulerosv2r7",
        "php-soap-5.4.16-45.h27.eulerosv2r7",
        "php-xml-5.4.16-45.h27.eulerosv2r7",
        "php-xmlrpc-5.4.16-45.h27.eulerosv2r7"];

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
