#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147033);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id(
    "CVE-2020-7068",
    "CVE-2020-7069",
    "CVE-2020-7070",
    "CVE-2020-7071"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : php (EulerOS-SA-2021-1566)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - In PHP versions 7.2.x below 7.2.33, 7.3.x below 7.3.21
    and 7.4.x below 7.4.9, while processing PHAR files
    using phar extension, phar_parse_zipfile could be
    tricked into accessing freed memory, which could lead
    to a crash or information disclosure.(CVE-2020-7068)

  - In PHP versions 7.2.x below 7.2.34, 7.3.x below 7.3.23
    and 7.4.x below 7.4.11, when PHP is processing incoming
    HTTP cookie values, the cookie names are url-decoded.
    This may lead to cookies with prefixes like __Host
    confused with cookies that decode to such prefix, thus
    leading to an attacker being able to forge cookie which
    is supposed to be secure. See also CVE-2020-8184 for
    more information.(CVE-2020-7070)

  - In PHP versions 7.2.x below 7.2.34, 7.3.x below 7.3.23
    and 7.4.x below 7.4.11, when AES-CCM mode is used with
    openssl_encrypt() function with 12 bytes IV, only first
    7 bytes of the IV is actually used. This can lead to
    both decreased security and incorrect encryption
    data.(CVE-2020-7069)

  - In PHP versions 7.3.x below 7.3.26, 7.4.x below 7.4.14
    and 8.0.0, when validating URL with functions like
    filter_var($url, FILTER_VALIDATE_URL), PHP will accept
    an URL with invalid password as valid URL. This may
    lead to functions that rely on URL being valid to
    mis-parse the URL and produce wrong data as components
    of the URL.(CVE-2020-7071)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1566
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83d43a69");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["php-7.2.10-1.h20.eulerosv2r8",
        "php-cli-7.2.10-1.h20.eulerosv2r8",
        "php-common-7.2.10-1.h20.eulerosv2r8"];

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
