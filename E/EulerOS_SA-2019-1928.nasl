#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128931);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-5590",
    "CVE-2015-8865",
    "CVE-2016-4537",
    "CVE-2016-4538",
    "CVE-2016-5096",
    "CVE-2016-5114",
    "CVE-2016-5771",
    "CVE-2016-5773",
    "CVE-2016-6289",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042"
  );
  script_bugtraq_id(
    75970
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : php (EulerOS-SA-2019-1928)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-5590)

  - Integer overflow in the virtual_file_ex function in
    TSRM/tsrm_virtual_cwd.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 allows remote
    attackers to cause a denial of service (stack-based
    buffer overflow) or possibly have unspecified other
    impact via a crafted extract operation on a ZIP
    archive.(CVE-2016-6289)

  - php_zip.c in the zip extension in PHP before 5.5.37,
    5.6.x before 5.6.23, and 7.x before 7.0.8 improperly
    interacts with the unserialize implementation and
    garbage collection, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (use-after-free and application crash) via crafted
    serialized data containing a ZipArchive
    object.(CVE-2016-5773)

  - spl_array.c in the SPL extension in PHP before 5.5.37
    and 5.6.x before 5.6.23 improperly interacts with the
    unserialize implementation and garbage collection,
    which allows remote attackers to execute arbitrary code
    or cause a denial of service (use-after-free and
    application crash) via crafted serialized
    data.(CVE-2016-5771)

  - An out-of-bounds write flaw was found in the
    fpm_log_write() logging function of PHP's FastCGI
    Process Manager service. A remote attacker could
    repeatedly send maliciously crafted requests to force
    FPM to exhaust file system space, creating a denial of
    service and preventing further logging.(CVE-2016-5114)

  - Integer overflow in the fread function in
    ext/standard/file.c in PHP before 5.5.36 and 5.6.x
    before 5.6.22 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact
    via a large integer in the second
    argument.(CVE-2016-5096)

  - The bcpowmod function in ext/bcmath/bcmath.c in PHP
    before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 modifies certain data structures without
    considering whether they are copies of the _zero_,
    _one_, or _two_ global variable, which allows remote
    attackers to cause a denial of service or possibly have
    unspecified other impact via a crafted
    call.(CVE-2016-4538)

  - The bcpowmod function in ext/bcmath/bcmath.c in PHP
    before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 accepts a negative integer for the scale
    argument, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via a crafted call.(CVE-2016-4537)

  - The file_check_mem function in funcs.c in file before
    5.23, as used in the Fileinfo component in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5,
    mishandles continuation-level jumps, which allows
    context-dependent attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly execute arbitrary code via a crafted magic
    file.(CVE-2015-8865)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and
    7.3.x below 7.3.6 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11040)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11042)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11041)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1928
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85a60e7f");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5773");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h14",
        "php-cli-5.4.16-45.h14",
        "php-common-5.4.16-45.h14"];

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
