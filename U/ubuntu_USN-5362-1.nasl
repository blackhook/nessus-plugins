#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5362-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159395);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4090",
    "CVE-2021-4155",
    "CVE-2021-42327",
    "CVE-2022-0001",
    "CVE-2022-0185",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-0492",
    "CVE-2022-0516",
    "CVE-2022-0742",
    "CVE-2022-0847",
    "CVE-2022-22942",
    "CVE-2022-23222",
    "CVE-2022-23960",
    "CVE-2022-25636"
  );
  script_xref(name:"USN", value:"5362-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Intel IOTG) vulnerabilities (USN-5362-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5362-1 advisory.

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - An out-of-bounds (OOB) memory write flaw was found in the NFSD in the Linux kernel. Missing sanity may
    lead to a write beyond bmval[bmlen-1] in nfsd4_decode_bitmap4 in fs/nfsd/nfs4xdr.c. In this flaw, a local
    attacker with user privilege may gain access to out-of-bounds memory, leading to a system integrity and
    confidentiality threat. (CVE-2021-4090)

  - dp_link_settings_write in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_debugfs.c in the Linux kernel
    through 5.14.14 allows a heap-based buffer overflow by an attacker who can write a string to the AMD GPU
    display drivers debug filesystem. There are no checks on size within parse_write_buffer_into_params when
    it uses the size of copy_from_user to copy a userspace buffer into a 40-byte heap buffer. (CVE-2021-42327)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem
    Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in
    case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local
    user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to
    legacy handling) could use this flaw to escalate their privileges on the system. (CVE-2022-0185)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends
    a packet with malicious content where the number of domain member nodes is higher than the 64 allowed.
    This flaw allows a remote user to crash the system or possibly escalate their privileges if they have
    access to the TIPC network. (CVE-2022-0435)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A vulnerability was found in kvm_s390_guest_sida_op in the arch/s390/kvm/kvm-s390.c function in KVM for
    s390 in the Linux kernel. This flaw allows a local attacker with a normal user privilege to obtain
    unauthorized memory write access. This flaw affects Linux kernel versions prior to 5.17-rc4.
    (CVE-2022-0516)

  - Memory leak in icmp6 implementation in Linux Kernel 5.13+ allows a remote attacker to DoS a host by making
    it go out-of-memory via icmp6 packets of type 130 or 131. We recommend upgrading past commit
    2d3916f3189172d5c69d33065c3c21119fe539fc. (CVE-2022-0742)

  - A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

  - kernel/bpf/verifier.c in the Linux kernel through 5.15.14 allows local users to gain privileges because of
    the availability of pointer arithmetic via certain *_OR_NULL pointer types. (CVE-2022-23222)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB. An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches. Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - net/netfilter/nf_dup_netdev.c in the Linux kernel 5.4 through 5.6.10 allows local users to gain privileges
    because of a heap out-of-bounds write. This is related to nf_tables_offload. (CVE-2022-25636)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5362-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-cloud-tools-5.13.0-1010");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-headers-5.13.0-1010");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-source-5.13.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-tools-5.13.0-1010");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-intel-5.13-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.13.0-1010-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-intel");
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
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-intel', 'pkgver': '5.13.0.1010.11'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-headers-intel', 'pkgver': '5.13.0.1010.11'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-image-intel', 'pkgver': '5.13.0.1010.11'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel', 'pkgver': '5.13.0.1010.11'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-cloud-tools-5.13.0-1010', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-cloud-tools-common', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-headers-5.13.0-1010', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-source-5.13.0', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-tools-5.13.0-1010', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-tools-common', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-intel-5.13-tools-host', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.13.0-1010-intel', 'pkgver': '5.13.0-1010.10'},
    {'osver': '20.04', 'pkgname': 'linux-tools-intel', 'pkgver': '5.13.0.1010.11'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.13.0-1010-intel / etc');
}
