#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5267-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158125);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2021-3640", "CVE-2021-3752", "CVE-2021-42739");
  script_xref(name:"USN", value:"5267-3");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel (Raspberry Pi) vulnerabilities (USN-5267-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5267-3 advisory.

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - A flaw use-after-free in function sco_sock_sendmsg() of the Linux kernel HCI subsystem was found in the
    way user calls ioct UFFDIO_REGISTER or other way triggers race condition of the call sco_conn_del()
    together with the call sco_sock_sendmsg() with the expected controllable faulting memory page. A
    privileged local user could use this flaw to crash the system or escalate their privileges on the system.
    (CVE-2021-3640)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5267-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1052-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1052-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1052-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1052-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.4.0-1052");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1052-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04-edge");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.54'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.54'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-raspi', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-headers-5.4.0-1052', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-tools-5.4.0-1052', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1052-raspi', 'pkgver': '5.4.0-1052.58'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04', 'pkgver': '5.4.0.1052.86'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1052.86'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.4.0-1052-raspi / linux-headers-5.4.0-1052-raspi / etc');
}
