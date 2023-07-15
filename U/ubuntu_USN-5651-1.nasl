#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5651-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165668);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-40617");
  script_xref(name:"USN", value:"5651-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : strongSwan vulnerability (USN-5651-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5651-1 advisory.

  - strongSwan before 5.9.8 allows remote attackers to cause a denial of service in the revocation plugin by
    sending a crafted end-entity (and intermediate CA) certificate that contains a CRL/OCSP URL that points to
    a server (under the attacker's control) that doesn't properly respond but (for example) just does nothing
    after the initial TCP handshake, or sends an excessive amount of application data. (CVE-2022-40617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5651-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:charon-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:charon-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-extauth-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcharon-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan-extra-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrongswan-standard-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-charon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-libcharon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-scepclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-starter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-swanctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-ifmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-pdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:strongswan-tnc-server");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'charon-cmd', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'charon-systemd', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libcharon-standard-plugins', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libstrongswan', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-scepclient', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-tnc-base', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-tnc-client', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-tnc-ifmap', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-tnc-pdp', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '18.04', 'pkgname': 'strongswan-tnc-server', 'pkgver': '5.6.2-1ubuntu2.9'},
    {'osver': '20.04', 'pkgname': 'charon-cmd', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'charon-systemd', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libcharon-standard-plugins', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libstrongswan', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-scepclient', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-base', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-client', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-ifmap', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-pdp', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '20.04', 'pkgname': 'strongswan-tnc-server', 'pkgver': '5.8.2-1ubuntu3.5'},
    {'osver': '22.04', 'pkgname': 'charon-cmd', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'charon-systemd', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libcharon-extauth-plugins', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libcharon-extra-plugins', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libstrongswan', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libstrongswan-extra-plugins', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libstrongswan-standard-plugins', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-charon', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-libcharon', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-nm', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-pki', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-scepclient', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-starter', 'pkgver': '5.9.5-2ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'strongswan-swanctl', 'pkgver': '5.9.5-2ubuntu2.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'charon-cmd / charon-systemd / libcharon-extauth-plugins / etc');
}
