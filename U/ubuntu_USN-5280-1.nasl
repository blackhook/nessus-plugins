#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5280-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157882);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2020-23903");
  script_xref(name:"USN", value:"5280-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 : Speex vulnerability (USN-5280-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-5280-1 advisory.

  - A Divide by Zero vulnerability in the function static int read_samples of Speex v1.2 allows attackers to
    cause a denial of service (DoS) via a crafted WAV file. (CVE-2020-23903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5280-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-23903");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspeex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspeex1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspeexdsp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libspeexdsp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:speex");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libspeex-dev', 'pkgver': '1.2~rc1.2-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libspeex1', 'pkgver': '1.2~rc1.2-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libspeexdsp-dev', 'pkgver': '1.2~rc1.2-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'libspeexdsp1', 'pkgver': '1.2~rc1.2-1ubuntu1+esm1'},
    {'osver': '16.04', 'pkgname': 'speex', 'pkgver': '1.2~rc1.2-1ubuntu1+esm1'},
    {'osver': '18.04', 'pkgname': 'libspeex-dev', 'pkgver': '1.2~rc1.2-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libspeex1', 'pkgver': '1.2~rc1.2-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libspeexdsp-dev', 'pkgver': '1.2~rc1.2-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'libspeexdsp1', 'pkgver': '1.2~rc1.2-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'speex', 'pkgver': '1.2~rc1.2-1ubuntu2.1'},
    {'osver': '20.04', 'pkgname': 'libspeex-dev', 'pkgver': '1.2~rc1.2-1.1ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libspeex1', 'pkgver': '1.2~rc1.2-1.1ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libspeexdsp-dev', 'pkgver': '1.2~rc1.2-1.1ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libspeexdsp1', 'pkgver': '1.2~rc1.2-1.1ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'speex', 'pkgver': '1.2~rc1.2-1.1ubuntu1.20.04.1'},
    {'osver': '21.10', 'pkgname': 'libspeex-dev', 'pkgver': '1.2~rc1.2-1.1ubuntu1.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libspeex1', 'pkgver': '1.2~rc1.2-1.1ubuntu1.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libspeexdsp-dev', 'pkgver': '1.2~rc1.2-1.1ubuntu1.21.10.1'},
    {'osver': '21.10', 'pkgname': 'libspeexdsp1', 'pkgver': '1.2~rc1.2-1.1ubuntu1.21.10.1'},
    {'osver': '21.10', 'pkgname': 'speex', 'pkgver': '1.2~rc1.2-1.1ubuntu1.21.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libspeex-dev / libspeex1 / libspeexdsp-dev / libspeexdsp1 / speex');
}
