##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5390-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160478);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-1015", "CVE-2022-1016", "CVE-2022-26490");
  script_xref(name:"USN", value:"5390-2");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (Raspberry Pi) vulnerabilities (USN-5390-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5390-2 advisory.

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem.
    This flaw allows a local user to cause an out-of-bounds write issue. (CVE-2022-1015)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5390-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26490");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.15.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.15.0-1006");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-1006-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.15.0-1006-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-nolpae");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-buildinfo-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-headers-raspi-nolpae', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-raspi', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-modules-extra-raspi-nolpae', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-raspi', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-raspi-headers-5.15.0-1006', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-raspi-nolpae', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-raspi-tools-5.15.0-1006', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1006-raspi', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-5.15.0-1006-raspi-nolpae', 'pkgver': '5.15.0-1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.15.0.1006.6'},
    {'osver': '22.04', 'pkgname': 'linux-tools-raspi-nolpae', 'pkgver': '5.15.0.1006.6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.15.0-1006-raspi / etc');
}
