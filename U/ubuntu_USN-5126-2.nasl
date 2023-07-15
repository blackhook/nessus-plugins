#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5126-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154709);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-25219");
  script_xref(name:"USN", value:"5126-2");
  script_xref(name:"IAVA", value:"2021-A-0525-S");

  script_name(english:"Ubuntu 16.04 LTS : Bind vulnerability (USN-5126-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5126-2 advisory.

  - In BIND 9.3.0 -> 9.11.35, 9.12.0 -> 9.16.21, and versions 9.9.3-S1 -> 9.11.35-S1 and 9.16.8-S1 ->
    9.16.21-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.18 of the BIND
    9.17 development branch, exploitation of broken authoritative servers using a flaw in response processing
    can cause degradation in BIND resolver performance. The way the lame cache is currently designed makes it
    possible for its internal data structures to grow almost infinitely, which may cause significant delays in
    client query processing. (CVE-2021-25219)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5126-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'bind9', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libbind-export-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libbind9-140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libdns-export162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libdns162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libirs-export141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libirs141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisc-export160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisc160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisccc140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisccfg-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'libisccfg140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'liblwres141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'},
    {'osver': '16.04', 'pkgname': 'lwresd', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.19+esm1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-host / bind9utils / dnsutils / host / libbind-dev / etc');
}
