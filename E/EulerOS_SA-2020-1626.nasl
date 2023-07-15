#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137468);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4545",
    "CVE-2013-6422",
    "CVE-2014-0139",
    "CVE-2016-3739",
    "CVE-2018-16840",
    "CVE-2019-15601"
  );
  script_bugtraq_id(
    63776,
    64431,
    66458
  );

  script_name(english:"EulerOS 2.0 SP2 : curl (EulerOS-SA-2020-1626)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A heap use-after-free flaw was found in curl versions
    from 7.59.0 through 7.61.1 in the code related to
    closing an easy handle. When closing and cleaning up an
    'easy' handle in the `Curl_close()` function, the
    library code first frees a struct (without nulling the
    pointer) and might then subsequently erroneously write
    to a struct field within that already freed
    struct.(CVE-2018-16840)

  - CURL before 7.68.0 lacks proper input validation, which
    allows users to create a `FILE:` URL that can make the
    client access a remote file using SMB (Windows-only
    issue).(CVE-2019-15601)

  - cURL and libcurl 7.18.0 through 7.32.0, when built with
    OpenSSL, disables the certificate CN and SAN name field
    verification (CURLOPT_SSL_VERIFYHOST) when the digital
    signature verification (CURLOPT_SSL_VERIFYPEER) is
    disabled, which allows man-in-the-middle attackers to
    spoof SSL servers via an arbitrary valid
    certificate.(CVE-2013-4545)

  - The GnuTLS backend in libcurl 7.21.4 through 7.33.0,
    when disabling digital signature verification
    (CURLOPT_SSL_VERIFYPEER), also disables the
    CURLOPT_SSL_VERIFYHOST check for CN or SAN host name
    fields, which makes it easier for remote attackers to
    spoof servers and conduct man-in-the-middle (MITM)
    attacks.(CVE-2013-6422)

  - cURL and libcurl 7.1 before 7.36.0, when using the
    OpenSSL, axtls, qsossl or gskit libraries for TLS,
    recognize a wildcard IP address in the subject's Common
    Name (CN) field of an X.509 certificate, which might
    allow man-in-the-middle attackers to spoof arbitrary
    SSL servers via a crafted certificate issued by a
    legitimate Certification Authority.(CVE-2014-0139)

  - The (1) mbed_connect_step1 function in
    lib/vtls/mbedtls.c and (2) polarssl_connect_step1
    function in lib/vtls/polarssl.c in cURL and libcurl
    before 7.49.0, when using SSLv3 or making a TLS
    connection to a URL that uses a numerical IP address,
    allow remote attackers to spoof servers via an
    arbitrary valid certificate.(CVE-2016-3739)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1626
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07808b2c");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl-devel");
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

pkgs = ["curl-7.29.0-35.h34",
        "libcurl-7.29.0-35.h34",
        "libcurl-devel-7.29.0-35.h34"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
