##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5354-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160588);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-21716");
  script_xref(name:"USN", value:"5354-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 22.04 LTS : Twisted vulnerability (USN-5354-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5354-2 advisory.

  - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0,
    Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH
    version identifier. This ends up with a buffer using all the available memory. The attach is a simple as
    `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known
    workarounds. (CVE-2022-21716)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5354-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21716");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-lore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-twisted-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-twisted");
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
if (! ('14.04' >< os_release || '16.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'python-twisted', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-bin', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-conch', 'pkgver': '1:13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-core', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-lore', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-mail', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-names', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-news', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-runner', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-web', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '14.04', 'pkgname': 'python-twisted-words', 'pkgver': '13.2.0-1ubuntu1.2+esm2'},
    {'osver': '16.04', 'pkgname': 'python-twisted', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-bin', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-conch', 'pkgver': '1:16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-core', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-mail', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-names', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-news', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-runner', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-web', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python-twisted-words', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '16.04', 'pkgname': 'python3-twisted', 'pkgver': '16.0.0-1ubuntu0.4+esm1'},
    {'osver': '22.04', 'pkgname': 'python3-twisted', 'pkgver': '22.1.0-2ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-twisted / python-twisted-bin / python-twisted-conch / etc');
}
