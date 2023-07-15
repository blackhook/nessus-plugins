##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4734-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146437);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-12695", "CVE-2021-0326");
  script_xref(name:"USN", value:"4734-1");
  script_xref(name:"CEA-ID", value:"CEA-2020-0050");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : wpa_supplicant and hostapd vulnerabilities (USN-4734-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4734-1 advisory.

  - The Open Connectivity Foundation UPnP specification before 2020-04-17 does not forbid the acceptance of a
    subscription request with a delivery URL on a different network segment than the fully qualified event-
    subscription URL, aka the CallStranger issue. (CVE-2020-12695)

  - In p2p_copy_client_info of p2p.c, there is a possible out of bounds write due to a missing bounds check.
    This could lead to remote code execution if the target device is performing a Wi-Fi Direct search, with no
    additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-172937525 (CVE-2021-0326)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4734-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0326");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:wpasupplicant-udeb");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'hostapd', 'pkgver': '1:2.4-0ubuntu6.7'},
    {'osver': '16.04', 'pkgname': 'wpagui', 'pkgver': '2.4-0ubuntu6.7'},
    {'osver': '16.04', 'pkgname': 'wpasupplicant', 'pkgver': '2.4-0ubuntu6.7'},
    {'osver': '16.04', 'pkgname': 'wpasupplicant-udeb', 'pkgver': '2.4-0ubuntu6.7'},
    {'osver': '18.04', 'pkgname': 'hostapd', 'pkgver': '2:2.6-15ubuntu2.7'},
    {'osver': '18.04', 'pkgname': 'wpagui', 'pkgver': '2:2.6-15ubuntu2.7'},
    {'osver': '18.04', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.6-15ubuntu2.7'},
    {'osver': '18.04', 'pkgname': 'wpasupplicant-udeb', 'pkgver': '2:2.6-15ubuntu2.7'},
    {'osver': '20.04', 'pkgname': 'hostapd', 'pkgver': '2:2.9-1ubuntu4.2'},
    {'osver': '20.04', 'pkgname': 'wpagui', 'pkgver': '2:2.9-1ubuntu4.2'},
    {'osver': '20.04', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.9-1ubuntu4.2'},
    {'osver': '20.04', 'pkgname': 'wpasupplicant-udeb', 'pkgver': '2:2.9-1ubuntu4.2'},
    {'osver': '20.10', 'pkgname': 'hostapd', 'pkgver': '2:2.9-1ubuntu8.1'},
    {'osver': '20.10', 'pkgname': 'wpagui', 'pkgver': '2:2.9-1ubuntu8.1'},
    {'osver': '20.10', 'pkgname': 'wpasupplicant', 'pkgver': '2:2.9-1ubuntu8.1'},
    {'osver': '20.10', 'pkgname': 'wpasupplicant-udeb', 'pkgver': '2:2.9-1ubuntu8.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hostapd / wpagui / wpasupplicant / wpasupplicant-udeb');
}