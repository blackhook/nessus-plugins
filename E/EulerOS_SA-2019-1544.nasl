#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124997);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4248",
    "CVE-2014-2497",
    "CVE-2014-3515",
    "CVE-2014-3668",
    "CVE-2014-3670",
    "CVE-2014-9427",
    "CVE-2014-9705",
    "CVE-2015-0231",
    "CVE-2015-3412",
    "CVE-2015-4021",
    "CVE-2015-4024",
    "CVE-2015-4148",
    "CVE-2015-4598",
    "CVE-2015-4599",
    "CVE-2015-4602",
    "CVE-2015-4603",
    "CVE-2015-4604",
    "CVE-2015-4605",
    "CVE-2018-10546",
    "CVE-2018-10548"
  );
  script_bugtraq_id(
    61776,
    66233,
    68237,
    70665,
    70666,
    71833,
    72539,
    73031,
    74700,
    74903,
    75103,
    75233,
    75241,
    75244,
    75249,
    75250,
    75251,
    75252
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : php (EulerOS-SA-2019-1544)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - An integer underflow flaw leading to out-of-bounds
    memory access was found in the way PHP's Phar extension
    parsed Phar archives. A specially crafted archive could
    cause PHP to crash or, possibly, execute arbitrary code
    when opened.(CVE-2015-4021)

  - An out of bounds read flaw was found in the way the
    xmlrpc extension parsed dates in the ISO 8601 format. A
    specially crafted XML-RPC request or response could
    possibly cause a PHP application to
    crash.(CVE-2014-3668)

  - It was found that certain PHP functions did not
    properly handle file names containing a NULL character.
    A remote attacker could possibly use this flaw to make
    a PHP script access unexpected files and bypass
    intended file system access
    restrictions.(CVE-2015-4598)

  - A flaw was found in the way PHP handled malformed
    source files when running in CGI mode. A specially
    crafted PHP file could cause PHP CGI to
    crash.(CVE-2014-9427)

  - An issue was discovered in PHP before 5.6.36, 7.0.x
    before 7.0.30, 7.1.x before 7.1.17, and 7.2.x before
    7.2.5. ext/ldap/ldap.c allows remote LDAP servers to
    cause a denial of service (NULL pointer dereference and
    application crash) because of mishandling of the
    ldap_get_dn return value.(CVE-2018-10548)

  - An infinite loop vulnerability was found in
    ext/iconv/iconv.c in PHP due to the iconv stream not
    rejecting invalid multibyte sequences. A remote
    attacker could use this vulnerability to hang the php
    process and consume resources.(CVE-2018-10546)

  - The openssl_x509_parse function in openssl.c in the
    OpenSSL module in PHP before 5.4.18 and 5.5.x before
    5.5.2 does not properly handle a '\\0' character in a
    domain name in the Subject Alternative Name field of an
    X.509 certificate, which allows man-in-the-middle
    attackers to spoof arbitrary SSL servers via a crafted
    certificate issued by a legitimate Certification
    Authority, a related issue to
    CVE-2009-2408.(CVE-2013-4248)

  - A use-after-free flaw was found in the way PHP's
    unserialize() function processed data. If a remote
    attacker was able to pass crafted input to PHP's
    unserialize() function, they could cause the PHP
    interpreter to crash or, possibly, execute arbitrary
    code.(CVE-2015-0231)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-4602)

  - It was found that certain PHP functions did not
    properly handle file names containing a NULL character.
    A remote attacker could possibly use this flaw to make
    a PHP script access unexpected files and bypass
    intended file system access
    restrictions.(CVE-2015-3412)

  - The mcopy function in softmagic.c in file 5.x, as used
    in the Fileinfo component in PHP before 5.4.40, 5.5.x
    before 5.5.24, and 5.6.x before 5.6.8, does not
    properly restrict a certain offset value, which allows
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted string that is mishandled by a 'Python
    script text executable' rule.(CVE-2015-4605)

  - A heap buffer overflow flaw was found in the
    enchant_broker_request_dict() function of PHP's enchant
    extension. A specially crafted tag input could possibly
    cause a PHP application to crash.(CVE-2014-9705)

  - A buffer overflow flaw was found in the Exif extension.
    A specially crafted JPEG or TIFF file could cause a PHP
    application using the exif_thumbnail() function to
    crash or, possibly, execute arbitrary code with the
    privileges of the user running that PHP
    application.(CVE-2014-3670)

  - A flaws was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-4148)

  - A type confusion issue was found in the SPL ArrayObject
    and SPLObjectStorage classes' unserialize() method. A
    remote attacker able to submit specially crafted input
    to a PHP application, which would then unserialize this
    input using one of the aforementioned methods, could
    use this flaw to execute arbitrary code with the
    privileges of the user running that PHP
    application.(CVE-2014-3515)

  - The mget function in softmagic.c in file 5.x, as used
    in the Fileinfo component in PHP before 5.4.40, 5.5.x
    before 5.5.24, and 5.6.x before 5.6.8, does not
    properly maintain a certain pointer relationship, which
    allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted string that is mishandled by a 'Python
    script text executable' rule.(CVE-2015-4604)

  - A NULL pointer dereference flaw was found in the
    gdImageCreateFromXpm() function of PHP's gd extension.
    A remote attacker could use this flaw to crash a PHP
    application using gd via a specially crafted X PixMap
    (XPM) file.(CVE-2014-2497)

  - A flaw was found in the way PHP parsed multipart HTTP
    POST requests. A specially crafted request could cause
    PHP to use an excessive amount of CPU
    time.(CVE-2015-4024)

  - Multiple flaws were discovered in the way PHP's Soap
    extension performed object unserialization. Specially
    crafted input processed by the unserialize() function
    could cause a PHP application to disclose portion of
    its memory or crash.(CVE-2015-4599)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-4603)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1544
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb62c9b4");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
