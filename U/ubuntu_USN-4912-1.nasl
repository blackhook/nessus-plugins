##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4912-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148494);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-0423",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-14351",
    "CVE-2020-14390",
    "CVE-2020-25285",
    "CVE-2020-25645",
    "CVE-2020-25669",
    "CVE-2020-27830",
    "CVE-2020-36158",
    "CVE-2021-3178",
    "CVE-2021-3411",
    "CVE-2021-20194",
    "CVE-2021-29154"
  );
  script_xref(name:"USN", value:"4912-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-4912-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4912-1 advisory.

  - In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could
    lead to local escalation of privilege in the kernel with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-161151868References: N/A (CVE-2020-0423)

  - In various methods of hid-multitouch.c, there is a possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel (CVE-2020-0465)

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c, there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-147802478References: Upstream kernel (CVE-2020-0466)

  - A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-14351)

  - A flaw was found in the Linux kernel in versions before 5.9-rc6. When changing screen size, an out-of-
    bounds memory write can occur leading to memory corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out. (CVE-2020-14390)

  - A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified
    other impact, aka CID-17743798d812. (CVE-2020-25285)

  - A flaw was found in the Linux kernel in versions before 5.9-rc7. Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read the traffic unencrypted. The main threat from
    this vulnerability is to data confidentiality. (CVE-2020-25645)

  - mwifiex_cmd_802_11_ad_hoc_start in drivers/net/wireless/marvell/mwifiex/join.c in the Linux kernel through
    5.10.4 might allow remote attackers to execute arbitrary code via a long SSID value, aka CID-5c455c5ab332.
    (CVE-2020-36158)

  - ** DISPUTED ** fs/nfsd/nfs3xdr.c in the Linux kernel through 5.10.8, when there is an NFS export of a
    subdirectory of a filesystem, allows remote attackers to traverse to other parts of the filesystem via
    READDIRPLUS. NOTE: some parties argue that such a subdirectory export is not intended to prevent this
    attack; see also the exports(5) no_subtree_check default behavior. (CVE-2021-3178)

  - A flaw was found in the Linux kernel in versions prior to 5.10. A violation of memory access was found
    while detecting a padding of int3 in the linking state. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-3411)

  - There is a vulnerability in the linux kernel versions higher than 5.2 (if kernel compiled with config
    params CONFIG_BPF_SYSCALL=y , CONFIG_BPF=y , CONFIG_CGROUPS=y , CONFIG_CGROUP_BPF=y ,
    CONFIG_HARDENED_USERCOPY not set, and BPF hook to getsockopt is registered). As result of BPF execution,
    the local user can trigger bug in __cgroup_bpf_run_filter_getsockopt() function that can lead to heap
    overflow (because of non-hardened usercopy). The impact of attack could be deny of service or possibly
    privileges escalation. (CVE-2021-20194)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4912-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-image-5.6.0-1053-oem and / or linux-image-oem-20.04 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.6.0-1053-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-0423', 'CVE-2020-0465', 'CVE-2020-0466', 'CVE-2020-14351', 'CVE-2020-14390', 'CVE-2020-25285', 'CVE-2020-25645', 'CVE-2020-25669', 'CVE-2020-27830', 'CVE-2020-36158', 'CVE-2021-3178', 'CVE-2021-3411', 'CVE-2021-20194', 'CVE-2021-29154');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4912-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-image-5.6.0-1053-oem', 'pkgver': '5.6.0-1053.57'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.6.0.1053.49'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.6.0-1053-oem / linux-image-oem-20.04');
}