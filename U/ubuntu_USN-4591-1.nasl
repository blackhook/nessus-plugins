##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4591-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141541);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-12351", "CVE-2020-12352");
  script_xref(name:"USN", value:"4591-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-4591-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4591-1 advisory. Note that Nessus has not tested for this issue but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4591-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1090-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1100-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-122-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-122-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-122-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1022-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-52-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-52-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-52-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-12351', 'CVE-2020-12352');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4591-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-122-generic', 'pkgver': '4.15.0-122.124~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-122-generic-lpae', 'pkgver': '4.15.0-122.124~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-122-lowlatency', 'pkgver': '4.15.0-122.124~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.122.122'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.122.122'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1090-snapdragon', 'pkgver': '4.15.0-1090.99'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1100-oem', 'pkgver': '4.15.0-1100.110'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-122-generic', 'pkgver': '4.15.0-122.124'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-122-generic-lpae', 'pkgver': '4.15.0-122.124'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-122-lowlatency', 'pkgver': '4.15.0-122.124'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1022-raspi', 'pkgver': '5.4.0-1022.25~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-52-generic', 'pkgver': '5.4.0-52.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-52-generic-lpae', 'pkgver': '5.4.0-52.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-52-lowlatency', 'pkgver': '5.4.0-52.57~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.1100.104'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1022.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1022.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1090.93'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.122.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.52.57~18.04.46'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1022-raspi', 'pkgver': '5.4.0-1022.25'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-52-generic', 'pkgver': '5.4.0-52.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-52-generic-lpae', 'pkgver': '5.4.0-52.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-52-lowlatency', 'pkgver': '5.4.0-52.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1022.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.52.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.4.0.52.55'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-4.15.0-1090-snapdragon / linux-image-4.15.0-1100-oem / etc');
}