#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4965-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149907);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-32547",
    "CVE-2021-32548",
    "CVE-2021-32549",
    "CVE-2021-32550",
    "CVE-2021-32551",
    "CVE-2021-32552",
    "CVE-2021-32553",
    "CVE-2021-32554",
    "CVE-2021-32555",
    "CVE-2021-32556",
    "CVE-2021-32557"
  );
  script_xref(name:"USN", value:"4965-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : Apport vulnerabilities (USN-4965-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4965-1 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4965-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-noui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dh-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-problem-report");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'apport', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'python-apport', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'python-problem-report', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '18.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.9-0ubuntu7.24'},
    {'osver': '20.04', 'pkgname': 'apport', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.11-0ubuntu27.18'},
    {'osver': '20.10', 'pkgname': 'apport', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'apport-gtk', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'apport-kde', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'apport-noui', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'apport-retrace', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'dh-apport', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'python3-apport', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '20.10', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.11-0ubuntu50.7'},
    {'osver': '21.04', 'pkgname': 'apport', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.11-0ubuntu65.1'},
    {'osver': '21.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.11-0ubuntu65.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apport / apport-gtk / apport-kde / apport-noui / apport-retrace / etc');
}