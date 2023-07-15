##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5399-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160444);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-25637",
    "CVE-2021-3631",
    "CVE-2021-3667",
    "CVE-2021-3975",
    "CVE-2021-4147",
    "CVE-2022-0897"
  );
  script_xref(name:"USN", value:"5399-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : libvirt vulnerabilities (USN-5399-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5399-1 advisory.

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

  - A flaw was found in libvirt while it generates SELinux MCS category pairs for VMs' dynamic labels. This
    flaw allows one exploited guest to access files labeled for another guest, resulting in the breaking out
    of sVirt confinement. The highest threat from this vulnerability is to confidentiality and integrity.
    (CVE-2021-3631)

  - An improper locking issue was found in the virStoragePoolLookupByTargetPath API of libvirt. It occurs in
    the storagePoolLookupByTargetPath function where a locked virStoragePoolObj object is not properly
    released on ACL permission failure. Clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to acquire the lock and prevent other users from accessing storage
    pool/volume APIs, resulting in a denial of service condition. The highest threat from this vulnerability
    is to system availability. (CVE-2021-3667)

  - A flaw was found in the libvirt libxl driver. A malicious guest could continuously reboot itself and cause
    libvirtd on the host to deadlock or crash, resulting in a denial of service condition. (CVE-2021-4147)

  - A flaw was found in the libvirt nwfilter driver. The virNWFilterObjListNumOfNWFilters method failed to
    acquire the `driver->nwfilters` mutex before iterating over virNWFilterObj instances. There was no
    protection to stop another thread from concurrently modifying the `driver->nwfilters` object. This flaw
    allows a malicious, unprivileged user to exploit this issue via libvirt's API virConnectNumOfNWFilters to
    crash the network filter management daemon (libvirtd/virtnwfilterd). (CVE-2022-0897)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5399-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-sheepdog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-storage-zfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-vbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-driver-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-daemon-system-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libnss-libvirt', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-bin', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-clients', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-sheepdog', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-dev', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '18.04', 'pkgname': 'libvirt0', 'pkgver': '4.0.0-1ubuntu8.21'},
    {'osver': '20.04', 'pkgname': 'libnss-libvirt', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-clients', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-lxc', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-qemu', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-vbox', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-driver-xen', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system-systemd', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-daemon-system-sysv', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-dev', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-sanlock', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt-wireshark', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '20.04', 'pkgname': 'libvirt0', 'pkgver': '6.0.0-0ubuntu8.16'},
    {'osver': '21.10', 'pkgname': 'libnss-libvirt', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-clients', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-config-network', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-config-nwfilter', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-lxc', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-qemu', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-storage-gluster', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-storage-iscsi-direct', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-storage-rbd', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-storage-zfs', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-vbox', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-driver-xen', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-system', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-system-systemd', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-daemon-system-sysv', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-dev', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-login-shell', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-sanlock', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt-wireshark', 'pkgver': '7.6.0-0ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libvirt0', 'pkgver': '7.6.0-0ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss-libvirt / libvirt-bin / libvirt-clients / libvirt-daemon / etc');
}
