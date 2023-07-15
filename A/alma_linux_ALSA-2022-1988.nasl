##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1988.
##

include('compat.inc');

if (description)
{
  script_id(161093);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2020-0404",
    "CVE-2020-4788",
    "CVE-2020-13974",
    "CVE-2020-27820",
    "CVE-2021-0941",
    "CVE-2021-3612",
    "CVE-2021-3669",
    "CVE-2021-3743",
    "CVE-2021-3744",
    "CVE-2021-3752",
    "CVE-2021-3759",
    "CVE-2021-3764",
    "CVE-2021-3772",
    "CVE-2021-3773",
    "CVE-2021-4002",
    "CVE-2021-4037",
    "CVE-2021-4083",
    "CVE-2021-4157",
    "CVE-2021-4197",
    "CVE-2021-4203",
    "CVE-2021-20322",
    "CVE-2021-21781",
    "CVE-2021-26401",
    "CVE-2021-29154",
    "CVE-2021-37159",
    "CVE-2021-41864",
    "CVE-2021-42739",
    "CVE-2021-43056",
    "CVE-2021-43389",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45485",
    "CVE-2021-45486",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0286",
    "CVE-2022-0322",
    "CVE-2022-1011"
  );
  script_xref(name:"ALSA", value:"2022:1988");

  script_name(english:"AlmaLinux 8 : kernel (ALSA-2022:1988)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:1988 advisory.

  - In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual
    root cause. This could lead to local escalation of privilege in the kernel with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream kernel (CVE-2020-0404)

  - IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under extenuating circumstances. IBM X-Force ID: 189296.
    (CVE-2020-4788)

  - An issue was discovered in the Linux kernel 4.4 through 5.7.1. drivers/tty/vt/keyboard.c has an integer
    overflow if k_ascii is called several times in a row, aka CID-b86dab054059. NOTE: Members in the community
    argue that the integer overflow does not lead to a security issue in this case. (CVE-2020-13974)

  - A vulnerability was found in Linux kernel, where a use-after-frees in nouveau's postclose() handler could
    happen if removing device (that is not common to remove video card physically without power-off, but same
    happens if unbind the driver). (CVE-2020-27820)

  - In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-154177719References:
    Upstream kernel (CVE-2021-0941)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - An out-of-bounds (OOB) memory read flaw was found in the Qualcomm IPC router protocol in the Linux kernel.
    A missing sanity check allows a local attacker to gain access to out-of-bounds memory, leading to a system
    crash or a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-3743)

  - A memory leak flaw was found in the Linux kernel in the ccp_run_aes_gcm_cmd() function in
    drivers/crypto/ccp/ccp-ops.c, which allows attackers to cause a denial of service (memory consumption).
    This vulnerability is similar with the older CVE-2019-18808. (CVE-2021-3744)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - A flaw in netfilter could allow a network-connected attacker to infer openvpn connection endpoint
    information for further use in traditional network attacks. (CVE-2021-3773)

  - A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some
    regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the
    memory pages. A local user could use this flaw to get unauthorized access to some data. (CVE-2021-4002)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - An out of memory bounds write flaw (1 or 2 bytes of memory) in the Linux kernel NFS subsystem was found in
    the way users use mirroring (replication of files with NFS). A user, having access to the NFS mount, could
    potentially use this flaw to crash the system or escalate privileges on the system. (CVE-2021-4157)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux
    kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source
    port randomization are indirectly affected as well. (CVE-2021-20322)

  - An information disclosure vulnerability exists in the ARM SIGPAGE functionality of Linux Kernel v5.4.66
    and v5.4.54. The latest version (5.11-rc4) seems to still be vulnerable. A userland application can read
    the contents of the sigpage, which can leak kernel memory contents. An attacker can read a process's
    memory at a specific offset to trigger this vulnerability. This was fixed in kernel releases: 4.14.222
    4.19.177 5.4.99 5.10.17 5.11 (CVE-2021-21781)

  - LFENCE/JMP (mitigation V2-2) may not sufficiently mitigate CVE-2017-5715 on some AMD CPUs.
    (CVE-2021-26401)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - hso_free_net_device in drivers/net/usb/hso.c in the Linux kernel through 5.13.4 calls unregister_netdev
    without checking for the NETREG_REGISTERED state, leading to a use-after-free and a double free.
    (CVE-2021-37159)

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel before 5.14.12 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - A heap-based buffer overflow flaw was found in the Linux kernel FireDTV media card driver, where the user
    calls the CA_SEND_MSG ioctl. This flaw allows a local user of the host machine to crash the system or
    escalate privileges on the system. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-42739)

  - An issue was discovered in the Linux kernel for powerpc before 5.14.15. It allows a malicious KVM guest to
    crash the host, when the host is running on Power8, due to an arch/powerpc/kvm/book3s_hv_rmhandlers.S
    implementation bug in the handling of the SRR1 register values. (CVE-2021-43056)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A flaw was found in the Linux kernel. A null pointer dereference in bond_ipsec_add_sa() may lead to local
    denial of service. (CVE-2022-0286)

  - A flaw was found in the sctp_make_strreset_req function in net/sctp/sm_make_chunk.c in the SCTP network
    protocol in the Linux kernel with a local user privilege access. In this flaw, an attempt to use more
    buffer than is allocated triggers a BUG_ON issue, leading to a denial of service (DOS). (CVE-2022-0322)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1988.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3773");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-0404', 'CVE-2020-4788', 'CVE-2020-13974', 'CVE-2020-27820', 'CVE-2021-0941', 'CVE-2021-3612', 'CVE-2021-3669', 'CVE-2021-3743', 'CVE-2021-3744', 'CVE-2021-3752', 'CVE-2021-3759', 'CVE-2021-3764', 'CVE-2021-3772', 'CVE-2021-3773', 'CVE-2021-4002', 'CVE-2021-4037', 'CVE-2021-4083', 'CVE-2021-4157', 'CVE-2021-4197', 'CVE-2021-4203', 'CVE-2021-20322', 'CVE-2021-21781', 'CVE-2021-26401', 'CVE-2021-29154', 'CVE-2021-37159', 'CVE-2021-41864', 'CVE-2021-42739', 'CVE-2021-43056', 'CVE-2021-43389', 'CVE-2021-43976', 'CVE-2021-44733', 'CVE-2021-45485', 'CVE-2021-45486', 'CVE-2022-0001', 'CVE-2022-0002', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-1011');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2022:1988');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-4.18.0-372.9.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.9.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-372.9.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
