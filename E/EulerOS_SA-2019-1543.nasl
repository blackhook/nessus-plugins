#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124996);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2014-3597",
    "CVE-2014-3669",
    "CVE-2014-4721",
    "CVE-2014-5120",
    "CVE-2014-8142",
    "CVE-2015-0232",
    "CVE-2015-0273",
    "CVE-2015-2348",
    "CVE-2015-2783",
    "CVE-2015-2787",
    "CVE-2015-3329",
    "CVE-2015-4022",
    "CVE-2015-4025",
    "CVE-2015-4026",
    "CVE-2015-4643",
    "CVE-2015-6834",
    "CVE-2015-6835",
    "CVE-2015-6836",
    "CVE-2015-6837",
    "CVE-2015-8873"
  );
  script_bugtraq_id(
    68423,
    69322,
    69375,
    70611,
    71791,
    72541,
    72701,
    73431,
    73434,
    74239,
    74240,
    74902,
    74904,
    75056,
    75291
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : php (EulerOS-SA-2019-1543)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A flaws was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2014-8142)

  - It was found that certain PHP functions did not
    properly handle file names containing a NULL character.
    A remote attacker could possibly use this flaw to make
    a PHP script access unexpected files and bypass
    intended file system access
    restrictions.(CVE-2015-4026)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6834)

  - It was found that certain PHP functions did not
    properly handle file names containing a NULL character.
    A remote attacker could possibly use this flaw to make
    a PHP script access unexpected files and bypass
    intended file system access
    restrictions.(CVE-2015-4025)

  - An integer overflow flaw was found in the way custom
    objects were unserialized. Specially crafted input
    processed by the unserialize() function could cause a
    PHP application to crash.(CVE-2014-3669)

  - It was found that PHP move_uploaded_file() function did
    not properly handle file names with a NULL character. A
    remote attacker could possibly use this flaw to make a
    PHP script access unexpected files and bypass intended
    file system access restrictions.(CVE-2015-2348)

  - An integer overflow flaw leading to a heap-based buffer
    overflow was found in the way PHP's FTP extension
    parsed file listing FTP server responses. A malicious
    FTP server could use this flaw to cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-4022)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6836)

  - A NULL pointer dereference flaw was found in the
    XSLTProcessor class in PHP. An attacker could use this
    flaw to cause a PHP application to crash if it
    performed Extensible Stylesheet Language (XSL)
    transformations using untrusted XSLT files and allowed
    the use of PHP functions to be used as XSLT functions
    within XSL stylesheets.(CVE-2015-6837)

  - It was found that PHP's gd extension did not properly
    handle file names with a null character. A remote
    attacker could possibly use this flaw to make a PHP
    application access unexpected files and bypass intended
    file system access restrictions.(CVE-2014-5120)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6835)

  - Stack consumption vulnerability in
    Zend/zend_exceptions.c in PHP before 5.4.44, 5.5.x
    before 5.5.28, and 5.6.x before 5.6.12 allows remote
    attackers to cause a denial of service (segmentation
    fault) via recursive method calls.(CVE-2015-8873)

  - An uninitialized pointer use flaw was found in PHP's
    Exif extension. A specially crafted JPEG or TIFF file
    could cause a PHP application using the
    exif_read_data() function to crash or, possibly,
    execute arbitrary code with the privileges of the user
    running that PHP application.(CVE-2015-0232)

  - A flaws was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-2787)

  - A buffer over-read flaw was found in PHP's phar (PHP
    Archive) paths implementation. A malicious script
    author could possibly use this flaw to disclose certain
    portions of server memory.(CVE-2015-2783)

  - A use-after-free flaw was found in the unserialize()
    function of PHP's DateTimeZone implementation. A
    malicious script author could possibly use this flaw to
    disclose certain portions of server
    memory.(CVE-2015-0273)

  - Multiple buffer over-read flaws were found in the
    php_parserr() function of PHP. A malicious DNS server
    or a man-in-the-middle attacker could possibly use this
    flaw to crash a PHP application that used the
    dns_get_record() function to perform a DNS
    query.(CVE-2014-3597)

  - A buffer overflow flaw was found in the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-3329)

  - Integer overflow in the ftp_genlist function in
    ext/ftp/ftp.c in PHP before 5.4.42, 5.5.x before
    5.5.26, and 5.6.x before 5.6.10 allows remote FTP
    servers to execute arbitrary code via a long reply to a
    LIST command, leading to a heap-based buffer overflow.
    NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2015-4022.(CVE-2015-4643)

  - A type confusion issue was found in PHP's phpinfo()
    function. A malicious script author could possibly use
    this flaw to disclose certain portions of server
    memory.(CVE-2014-4721)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a562103a");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6836");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-6835");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h9",
        "php-cli-5.4.16-45.h9",
        "php-common-5.4.16-45.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
