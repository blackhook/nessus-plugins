##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5416-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161062);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-1158",
    "CVE-2022-1516",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390"
  );
  script_xref(name:"USN", value:"5416-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-5416-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5416-1 advisory.

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - A flaw was found in KVM. When updating a guest's page table entry, vm_pgoff was improperly used as the
    offset to get the page's pfn. As vaddr and vm_pgoff are controllable by user-mode processes, this flaw
    allows unprivileged local users on the host to write outside the userspace region and potentially corrupt
    the kernel, resulting in a denial of service condition. (CVE-2022-1158)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5416-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-headers-5.14.0-1036");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-5.14.0-1036");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.14.0-1036-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-20.04d");
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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04b', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04c', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04d', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04b', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04c', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04d', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04b', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04c', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04d', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-headers-5.14.0-1036', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-5.14.0-1036', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-host', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.14.0-1036-oem', 'pkgver': '5.14.0-1036.40'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04b', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04c', 'pkgver': '5.14.0.1036.33'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04d', 'pkgver': '5.14.0.1036.33'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.14.0-1036-oem / linux-headers-5.14.0-1036-oem / etc');
}
