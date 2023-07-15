#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169569);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id(
    "CVE-2022-2602",
    "CVE-2022-3239",
    "CVE-2022-3303",
    "CVE-2022-3435",
    "CVE-2022-3523",
    "CVE-2022-3524",
    "CVE-2022-3534",
    "CVE-2022-3542",
    "CVE-2022-3545",
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2022-3577",
    "CVE-2022-3586",
    "CVE-2022-3606",
    "CVE-2022-3623",
    "CVE-2022-3625",
    "CVE-2022-3629",
    "CVE-2022-20409",
    "CVE-2022-20422",
    "CVE-2022-20423",
    "CVE-2022-39188",
    "CVE-2022-39189",
    "CVE-2022-39190",
    "CVE-2022-41850",
    "CVE-2022-42432",
    "CVE-2022-42703",
    "CVE-2022-43750"
  );

  script_name(english:"EulerOS 2.0 SP11 : kernel (EulerOS-SA-2023-1012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - In io_identity_cow of io_uring.c, there is a possible way to corrupt memory due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238177383References:
    Upstream kernel (CVE-2022-20409)

  - In emulation_proc_handler of armv8_deprecated.c, there is a possible way to corrupt memory due to a race
    condition. This could lead to local escalation of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid
    ID: A-237540956References: Upstream kernel (CVE-2022-20422)

  - In rndis_set_response of rndis.c, there is a possible out of bounds write due to an integer overflow. This
    could lead to local escalation of privilege if a malicious USB device is attached with no additional
    execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions:
    Android kernelAndroid ID: A-239842288References: Upstream kernel (CVE-2022-20423)

  - A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers
    em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system
    or potentially escalate their privileges on the system. (CVE-2022-3239)

  - A race condition flaw was found in the Linux kernel sound subsystem due to improper locking. It could lead
    to a NULL pointer dereference while handling the SNDCTL_DSP_SYNC ioctl. A privileged local user (root or
    member of the audio group) could use this flaw to crash the system, resulting in a denial of service
    condition (CVE-2022-3303)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown
    function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211020. (CVE-2022-3523)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as critical has been found in Linux Kernel. Affected is the function
    btf_dump_name_dups of the file tools/lib/bpf/btf_dump.c of the component libbpf. The manipulation leads to
    use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability
    is VDB-211032. (CVE-2022-3534)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function
    tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It
    is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this
    vulnerability. (CVE-2022-3566)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function inet6_stream_ops/inet6_dgram_ops of the component IPv6 Handler. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211090 is the identifier
    assigned to this vulnerability. (CVE-2022-3567)

  - An out-of-bounds memory write flaw was found in the Linux kernel's Kid-friendly Wired Controller driver.
    This flaw allows a local user to crash or potentially escalate their privileges on the system. It is in
    bigben_probe of drivers/hid/hid-bigbenff.c. The reason is incorrect assumption - bigben devices all have
    inputs. However, malicious devices can break this assumption, leaking to out-of-bound write.
    (CVE-2022-3577)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. This affects the
    function find_prog_by_sec_insn of the file tools/lib/bpf/libbpf.c of the component BPF. The manipulation
    leads to null pointer dereference. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211749 was assigned to this vulnerability. (CVE-2022-3606)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects
    the function vsock_connect of the file net/vmw_vsock/af_vsock.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this
    vulnerability. (CVE-2022-3629)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users
    can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED
    situations. (CVE-2022-39189)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-2602)

  - ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when
    announcing a new security problem. When the candidate has been publicized, the details for this candidate
    will be provided. (CVE-2022-42432)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c432ef65");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-5.10.0-60.18.0.50.h591.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h591.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h591.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h591.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h591.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
