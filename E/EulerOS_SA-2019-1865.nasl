#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128917);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-4116",
    "CVE-2015-5590",
    "CVE-2015-8865",
    "CVE-2015-8866",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-4537",
    "CVE-2016-4538",
    "CVE-2016-5096",
    "CVE-2016-5114",
    "CVE-2016-5771",
    "CVE-2016-5773",
    "CVE-2016-6289",
    "CVE-2016-7413"
  );
  script_bugtraq_id(
    75970
  );

  script_name(english:"EulerOS 2.0 SP2 : php (EulerOS-SA-2019-1865)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - An out-of-bounds write flaw was found in the
    fpm_log_write() logging function of PHP's FastCGI
    Process Manager service. A remote attacker could
    repeatedly send maliciously crafted requests to force
    FPM to exhaust file system space, creating a denial of
    service and preventing further logging.(CVE-2016-5114)

  - spl_array.c in the SPL extension in PHP before 5.5.37
    and 5.6.x before 5.6.23 improperly interacts with the
    unserialize implementation and garbage collection,
    which allows remote attackers to execute arbitrary code
    or cause a denial of service (use-after-free and
    application crash) via crafted serialized
    data.(CVE-2016-5771)

  - php_zip.c in the zip extension in PHP before 5.5.37,
    5.6.x before 5.6.23, and 7.x before 7.0.8 improperly
    interacts with the unserialize implementation and
    garbage collection, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (use-after-free and application crash) via crafted
    serialized data containing a ZipArchive
    object.(CVE-2016-5773)

  - Integer overflow in the fread function in
    ext/standard/file.c in PHP before 5.5.36 and 5.6.x
    before 5.6.22 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact
    via a large integer in the second
    argument.(CVE-2016-5096)

  - The bcpowmod function in ext/bcmath/bcmath.c in PHP
    before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 accepts a negative integer for the scale
    argument, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via a crafted call.(CVE-2016-4537)

  - The bcpowmod function in ext/bcmath/bcmath.c in PHP
    before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 modifies certain data structures without
    considering whether they are copies of the _zero_,
    _one_, or _two_ global variable, which allows remote
    attackers to cause a denial of service or possibly have
    unspecified other impact via a crafted
    call.(CVE-2016-4538)

  - The file_check_mem function in funcs.c in file before
    5.23, as used in the Fileinfo component in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5,
    mishandles continuation-level jumps, which allows
    context-dependent attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly execute arbitrary code via a crafted magic
    file.(CVE-2015-8865)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-5590)

  - Use-after-free vulnerability in the wddx_stack_destroy
    function in ext/wddx/wddx.c in PHP before 5.6.26 and
    7.x before 7.0.11 allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via a wddxPacket XML document that lacks an
    end-tag for a recordset field element, leading to
    mishandling in a wddx_deserialize call.(CVE-2016-7413)

  - Integer overflow in the phar_parse_pharfile function in
    ext/phar/phar.c in PHP before 5.6.30 and 7.0.x before
    7.0.15 allows remote attackers to cause a denial of
    service (memory consumption or application crash) via a
    truncated manifest entry in a PHAR
    archive.(CVE-2016-10159)

  - It was found that the exif_convert_any_to_int()
    function in PHP was vulnerable to floating point
    exceptions when parsing tags in image files. A remote
    attacker with the ability to upload a malicious image
    could crash PHP, causing a Denial of
    Service.(CVE-2016-10158)

  - ext/libxml/libxml.c in PHP before 5.5.22 and 5.6.x
    before 5.6.6, when PHP-FPM is used, does not isolate
    each thread from libxml_disable_entity_loader changes
    in other threads, which allows remote attackers to
    conduct XML External Entity (XXE) and XML Entity
    Expansion (XEE) attacks via a crafted XML document, a
    related issue to CVE-2015-5161.(CVE-2015-8866)

  - Use-after-free vulnerability in the spl_ptr_heap_insert
    function in ext/spl/spl_heap.c in PHP before 5.5.27 and
    5.6.x before 5.6.11 allows remote attackers to execute
    arbitrary code by triggering a failed
    SplMinHeap::compare operation.(CVE-2015-4116)

  - Integer overflow in the virtual_file_ex function in
    TSRM/tsrm_virtual_cwd.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 allows remote
    attackers to cause a denial of service (stack-based
    buffer overflow) or possibly have unspecified other
    impact via a crafted extract operation on a ZIP
    archive.(CVE-2016-6289)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1865
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0529a90");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7413");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-42.h43",
        "php-cli-5.4.16-42.h43",
        "php-common-5.4.16-42.h43",
        "php-gd-5.4.16-42.h43",
        "php-ldap-5.4.16-42.h43",
        "php-mysql-5.4.16-42.h43",
        "php-odbc-5.4.16-42.h43",
        "php-pdo-5.4.16-42.h43",
        "php-pgsql-5.4.16-42.h43",
        "php-process-5.4.16-42.h43",
        "php-recode-5.4.16-42.h43",
        "php-soap-5.4.16-42.h43",
        "php-xml-5.4.16-42.h43",
        "php-xmlrpc-5.4.16-42.h43"];

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
