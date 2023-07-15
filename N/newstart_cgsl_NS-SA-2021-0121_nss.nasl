#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0121. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154580);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-6829", "CVE-2020-12400", "CVE-2020-12403");
  script_xref(name:"IAVA", value:"2020-A-0391-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : nss Multiple Vulnerabilities (NS-SA-2021-0121)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has nss packages installed that are affected by multiple
vulnerabilities:

  - When converting coordinates from projective to affine, the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80
    and Firefox for Android < 80. (CVE-2020-12400)

  - A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS in versions before 3.55. When using
    multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling
    multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest
    threat from this vulnerability is to confidentiality and system availability. (CVE-2020-12403)

  - When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used; which
    leaked partial information about the nonce used during signature generation. Given an electro-magnetic
    trace of a few signature generations, the private key could have been computed. This vulnerability affects
    Firefox < 80 and Firefox for Android < 80. (CVE-2020-6829)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0121");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12400");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12403");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-6829");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL nss packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn-freebl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'nss-3.53.1-17.el8_3',
    'nss-debuginfo-3.53.1-17.el8_3',
    'nss-debugsource-3.53.1-17.el8_3',
    'nss-devel-3.53.1-17.el8_3',
    'nss-pkcs11-devel-3.53.1-17.el8_3',
    'nss-softokn-3.53.1-17.el8_3',
    'nss-softokn-debuginfo-3.53.1-17.el8_3',
    'nss-softokn-devel-3.53.1-17.el8_3',
    'nss-softokn-freebl-3.53.1-17.el8_3',
    'nss-softokn-freebl-debuginfo-3.53.1-17.el8_3',
    'nss-softokn-freebl-devel-3.53.1-17.el8_3',
    'nss-sysinit-3.53.1-17.el8_3',
    'nss-sysinit-debuginfo-3.53.1-17.el8_3',
    'nss-tools-3.53.1-17.el8_3',
    'nss-tools-debuginfo-3.53.1-17.el8_3',
    'nss-util-3.53.1-17.el8_3',
    'nss-util-debuginfo-3.53.1-17.el8_3',
    'nss-util-devel-3.53.1-17.el8_3'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nss');
}
