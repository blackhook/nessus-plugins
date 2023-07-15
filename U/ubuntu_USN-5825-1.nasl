#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5825-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170644);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-28321");
  script_xref(name:"USN", value:"5825-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : PAM vulnerability (USN-5825-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
a vulnerability as referenced in the USN-5825-1 advisory.

  - The Linux-PAM package before 1.5.2-6.1 for openSUSE Tumbleweed allows authentication bypass for SSH
    logins. The pam_access.so module doesn't correctly restrict login if a user tries to connect from an IP
    address that is not resolvable via DNS. In such conditions, a user with denied access to a machine can
    still get access. NOTE: the relevance of this issue is largely limited to openSUSE Tumbleweed and openSUSE
    Factory; it does not affect Linux-PAM upstream. (CVE-2022-28321)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5825-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-cracklib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-modules-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam0g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam0g-dev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libpam-cracklib', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libpam-modules', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libpam-modules-bin', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libpam-runtime', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libpam0g', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '16.04', 'pkgname': 'libpam0g-dev', 'pkgver': '1.1.8-3.2ubuntu2.3+esm2'},
    {'osver': '18.04', 'pkgname': 'libpam-cracklib', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpam-modules', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpam-modules-bin', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpam-runtime', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpam0g', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpam0g-dev', 'pkgver': '1.1.8-3.6ubuntu2.18.04.4'},
    {'osver': '20.04', 'pkgname': 'libpam-cracklib', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '20.04', 'pkgname': 'libpam-modules', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '20.04', 'pkgname': 'libpam-modules-bin', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '20.04', 'pkgname': 'libpam-runtime', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '20.04', 'pkgname': 'libpam0g', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '20.04', 'pkgname': 'libpam0g-dev', 'pkgver': '1.3.1-5ubuntu4.4'},
    {'osver': '22.04', 'pkgname': 'libpam-cracklib', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libpam-modules', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libpam-modules-bin', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libpam-runtime', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libpam0g', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'libpam0g-dev', 'pkgver': '1.4.0-11ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'libpam-modules', 'pkgver': '1.5.2-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libpam-modules-bin', 'pkgver': '1.5.2-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libpam-runtime', 'pkgver': '1.5.2-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libpam0g', 'pkgver': '1.5.2-2ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libpam0g-dev', 'pkgver': '1.5.2-2ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpam-cracklib / libpam-modules / libpam-modules-bin / etc');
}
