#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4934-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149253);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-28007",
    "CVE-2020-28008",
    "CVE-2020-28009",
    "CVE-2020-28010",
    "CVE-2020-28011",
    "CVE-2020-28012",
    "CVE-2020-28013",
    "CVE-2020-28014",
    "CVE-2020-28015",
    "CVE-2020-28016",
    "CVE-2020-28017",
    "CVE-2020-28018",
    "CVE-2020-28019",
    "CVE-2020-28020",
    "CVE-2020-28021",
    "CVE-2020-28022",
    "CVE-2020-28023",
    "CVE-2020-28024",
    "CVE-2020-28025",
    "CVE-2020-28026",
    "CVE-2021-27216"
  );
  script_xref(name:"USN", value:"4934-1");
  script_xref(name:"IAVA", value:"2021-A-0216-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : Exim vulnerabilities (USN-4934-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4934-1 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4934-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eximon4");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'exim4', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'exim4-base', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'exim4-config', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'exim4-daemon-heavy', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'exim4-daemon-light', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'exim4-dev', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'eximon4', 'pkgver': '4.90.1-1ubuntu1.8'},
    {'osver': '20.04', 'pkgname': 'exim4', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'exim4-base', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'exim4-config', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'exim4-daemon-heavy', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'exim4-daemon-light', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'exim4-dev', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.04', 'pkgname': 'eximon4', 'pkgver': '4.93-13ubuntu1.5'},
    {'osver': '20.10', 'pkgname': 'exim4', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'exim4-base', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'exim4-config', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'exim4-daemon-heavy', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'exim4-daemon-light', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'exim4-dev', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '20.10', 'pkgname': 'eximon4', 'pkgver': '4.94-7ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4-base', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4-config', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4-daemon-heavy', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4-daemon-light', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'exim4-dev', 'pkgver': '4.94-15ubuntu1.2'},
    {'osver': '21.04', 'pkgname': 'eximon4', 'pkgver': '4.94-15ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exim4 / exim4-base / exim4-config / exim4-daemon-heavy / etc');
}
