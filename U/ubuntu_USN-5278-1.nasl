#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5278-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157463);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2020-27820",
    "CVE-2021-4001",
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4155",
    "CVE-2021-4197",
    "CVE-2021-22600",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-39685",
    "CVE-2021-43975",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2021-45480",
    "CVE-2022-0264",
    "CVE-2022-0330",
    "CVE-2022-0382",
    "CVE-2022-22942",
    "CVE-2022-23222",
    "CVE-2022-24122"
  );
  script_xref(name:"USN", value:"5278-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-5278-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5278-1 advisory.

  - A vulnerability was found in Linux kernel, where a use-after-frees in nouveau's postclose() handler could
    happen if removing device (that is not common to remove video card physically without power-off, but same
    happens if unbind the driver). (CVE-2020-27820)

  - A race condition was found in the Linux kernel's ebpf verifier between bpf_map_update_elem and
    bpf_map_freeze due to a missing lock in kernel/bpf/syscall.c. In this flaw, a local user with a special
    privilege (cap_sys_admin or cap_bpf) can modify the frozen mapped address space. This flaw affects kernel
    versions prior to 5.16 rc2. (CVE-2021-4001)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28713)

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

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - An issue was discovered in the Linux kernel before 5.15.11. There is a memory leak in the
    __rds_conn_create() function in net/rds/connection.c in a certain combination of circumstances.
    (CVE-2021-45480)

  - A vulnerability was found in the Linux kernel's eBPF verifier when handling internal data structures.
    Internal memory locations could be returned to userspace. A local attacker with the permissions to insert
    eBPF code to the kernel can use this to leak internal kernel memory details defeating some of the exploit
    mitigations in place for the kernel. This flaws affects kernel versions < v5.16-rc6 (CVE-2022-0264)

  - kernel/bpf/verifier.c in the Linux kernel through 5.15.14 allows local users to gain privileges because of
    the availability of pointer arithmetic via certain *_OR_NULL pointer types. (CVE-2022-23222)

  - kernel/ucount.c in the Linux kernel 5.14 through 5.16.4, when unprivileged user namespaces are enabled,
    allows a use-after-free and privilege escalation because a ucounts object can outlive its namespace.
    (CVE-2022-24122)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5278-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.14.0-1022-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.14.0-1022-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.14.0-1022-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.14.0-1022-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.14.0-1022-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-20.04d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-headers-5.14.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-5.14.0-1022");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-5.14-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.14.0-1022-oem");
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
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-20.04d', 'pkgver': '5.14.0.1022.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04d', 'pkgver': '5.14.0.1022.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-oem-20.04d', 'pkgver': '5.14.0.1022.19'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-headers-5.14.0-1022', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-5.14.0-1022', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-oem-5.14-tools-host', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.14.0-1022-oem', 'pkgver': '5.14.0-1022.24'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-20.04d', 'pkgver': '5.14.0.1022.19'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.14.0-1022-oem / linux-headers-5.14.0-1022-oem / etc');
}
