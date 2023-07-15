#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5377-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159729);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4135",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2021-45469",
    "CVE-2021-45480",
    "CVE-2022-0435",
    "CVE-2022-0492",
    "CVE-2022-1055",
    "CVE-2022-27666"
  );
  script_xref(name:"USN", value:"5377-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (BlueField) vulnerabilities (USN-5377-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5377-1 advisory.

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - In __f2fs_setxattr in fs/f2fs/xattr.c in the Linux kernel through 5.15.11, there is an out-of-bounds
    memory access when an inode has an invalid last xattr entry. (CVE-2021-45469)

  - An issue was discovered in the Linux kernel before 5.15.11. There is a memory leak in the
    __rds_conn_create() function in net/rds/connection.c in a certain combination of circumstances.
    (CVE-2021-45480)

  - A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends
    a packet with malicious content where the number of domain member nodes is higher than the 64 allowed.
    This flaw allows a remote user to crash the system or possibly escalate their privileges if they have
    access to the TIPC network. (CVE-2022-0435)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A use-after-free exists in the Linux Kernel in tc_new_tfilter that could allow a local attacker to gain
    privilege escalation. The exploit requires unprivileged user namespaces. We recommend upgrading past
    commit 04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5 (CVE-2022-1055)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5377-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield-headers-5.4.0-1032");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-bluefield-tools-5.4.0-1032");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-1032-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-bluefield");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
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
    {'osver': '20.04', 'pkgname': 'linux-bluefield', 'pkgver': '5.4.0.1032.33'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-headers-5.4.0-1032', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-bluefield-tools-5.4.0-1032', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-headers-bluefield', 'pkgver': '5.4.0.1032.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-image-bluefield', 'pkgver': '5.4.0.1032.33'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-1032-bluefield', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-tools-bluefield', 'pkgver': '5.4.0.1032.33'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-bluefield / linux-bluefield-headers-5.4.0-1032 / etc');
}
