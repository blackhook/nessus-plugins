#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5292-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158162);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-3155",
    "CVE-2021-4120",
    "CVE-2021-44730",
    "CVE-2021-44731"
  );
  script_xref(name:"USN", value:"5292-3");

  script_name(english:"Ubuntu 16.04 LTS : snapd vulnerabilities (USN-5292-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5292-3 advisory.

  - snapd 2.54.2 and earlier created ~/snap directories in user home directories without specifying owner-only
    permissions. This could allow a local attacker to read information that should have been private. Fixed in
    snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1 (CVE-2021-3155)

  - snapd 2.54.2 fails to perform sufficient validation of snap content interface and layout paths, resulting
    in the ability for snaps to inject arbitrary AppArmor policy rules via malformed content interface and
    layout declarations and hence escape strict snap confinement. Fixed in snapd versions 2.54.3+18.04,
    2.54.3+20.04 and 2.54.3+21.10.1 (CVE-2021-4120)

  - snapd 2.54.2 did not properly validate the location of the snap-confine binary. A local attacker who can
    hardlink this binary to another location to cause snap-confine to execute other arbitrary binaries and
    hence gain privilege escalation. Fixed in snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1
    (CVE-2021-44730)

  - A race condition existed in the snapd 2.54.2 snap-confine binary when preparing a private mount namespace
    for a snap. This could allow a local attacker to gain root privileges by bind-mounting their own contents
    inside the snap's private mount namespace and causing snap-confine to execute arbitrary code and hence
    gain privilege escalation. Fixed in snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1
    (CVE-2021-44731)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5292-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44731");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-44730");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-snapcore-snapd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:golang-github-ubuntu-core-snappy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snap-confine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snapd-xdg-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubuntu-core-launcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubuntu-core-snapd-units");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubuntu-snappy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubuntu-snappy-cli");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'golang-github-snapcore-snapd-dev', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'golang-github-ubuntu-core-snappy-dev', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'snap-confine', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'snapd', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'snapd-xdg-open', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'ubuntu-core-launcher', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'ubuntu-core-snapd-units', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'ubuntu-snappy', 'pkgver': '2.54.3+16.04~esm2'},
    {'osver': '16.04', 'pkgname': 'ubuntu-snappy-cli', 'pkgver': '2.54.3+16.04~esm2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-snapcore-snapd-dev / etc');
}
