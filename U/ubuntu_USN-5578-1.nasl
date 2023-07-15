#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5578-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164376);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-31676");
  script_xref(name:"USN", value:"5578-1");
  script_xref(name:"IAVB", value:"2022-B-0029-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Open VM Tools vulnerability (USN-5578-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5578-1 advisory.

  - VMware Tools (12.0.0, 11.x.y and 10.x.y) contains a local privilege escalation vulnerability. A malicious
    actor with local non-administrative access to the Guest OS can escalate privileges as a root user in the
    virtual machine. (CVE-2022-31676)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5578-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:open-vm-tools-sdmp");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:11.0.5-4ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:11.0.5-4ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:11.0.5-4ubuntu0.18.04.2'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.3'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.3'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.3'},
    {'osver': '20.04', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:11.3.0-2ubuntu0~ubuntu20.04.3'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools', 'pkgver': '2:11.3.5-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-desktop', 'pkgver': '2:11.3.5-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-dev', 'pkgver': '2:11.3.5-1ubuntu4.1'},
    {'osver': '22.04', 'pkgname': 'open-vm-tools-sdmp', 'pkgver': '2:11.3.5-1ubuntu4.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'open-vm-tools / open-vm-tools-desktop / open-vm-tools-dev / etc');
}
