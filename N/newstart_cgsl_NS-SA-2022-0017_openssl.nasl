##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0017. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160849);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"IAVA", value:"2021-A-0103-S");
  script_xref(name:"IAVA", value:"2022-A-0038");
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssl Multiple Vulnerabilities (NS-SA-2022-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssl packages installed that are affected
by multiple vulnerabilities:

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissable length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to
    OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out
    of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should
    upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i).
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x). (CVE-2021-23840)

  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by
    OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on
    certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are
    affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x
    and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving
    public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should
    upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected
    1.0.2-1.0.2x). (CVE-2021-23841)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0017");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23840");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23841");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssl packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'openssl-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-crypto-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-debuginfo-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-devel-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-libs-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-perl-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite',
    'openssl-static-1.0.2k-22.el7_9.cgslv5.0.2.gbadae36.lite'
  ],
  'CGSL MAIN 5.04': [
    'openssl-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26',
    'openssl-debuginfo-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26',
    'openssl-devel-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26',
    'openssl-libs-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26',
    'openssl-perl-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26',
    'openssl-static-1.0.2k-22.el7_9.cgslv5.0.1.g5d3de26'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl');
}
