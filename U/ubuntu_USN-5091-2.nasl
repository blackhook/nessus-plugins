#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5091-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153801);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3679",
    "CVE-2021-33624",
    "CVE-2021-38160",
    "CVE-2021-38199",
    "CVE-2021-38204"
  );
  script_xref(name:"USN", value:"5091-2");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel (Raspberry Pi) vulnerabilities (USN-5091-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5091-2 advisory.

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because
    of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a
    side-channel attack, aka CID-9183671af6db. (CVE-2021-33624)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - fs/nfs/nfs4client.c in the Linux kernel before 5.13.4 has incorrect connection-setup ordering, which
    allows operators of remote NFSv4 servers to cause a denial of service (hanging of mounts) by arranging for
    those servers to be unreachable during trunking detection. (CVE-2021-38199)

  - drivers/usb/host/max3421-hcd.c in the Linux kernel before 5.13.6 allows physically proximate attackers to
    cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain
    situations. (CVE-2021-38204)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5091-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1044-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1044-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1044-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1044-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-headers-5.4.0-1044");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-5.4-tools-5.4.0-1044");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-headers-5.4.0-1044");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi-tools-5.4.0-1044");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1044-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2-hwe-18.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3679', 'CVE-2021-33624', 'CVE-2021-38160', 'CVE-2021-38199', 'CVE-2021-38204');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5091-2');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-modules-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-headers-5.4.0-1044', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-5.4-tools-5.4.0-1044', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-tools-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.47'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.47'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-headers-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-raspi', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-headers-5.4.0-1044', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-raspi-tools-5.4.0-1044', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1044-raspi', 'pkgver': '5.4.0-1044.48'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04', 'pkgver': '5.4.0.1044.79'},
    {'osver': '20.04', 'pkgname': 'linux-tools-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1044.79'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.4.0-1044-raspi / linux-headers-5.4.0-1044-raspi / etc');
}
