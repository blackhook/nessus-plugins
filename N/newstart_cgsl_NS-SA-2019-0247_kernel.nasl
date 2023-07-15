#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0247. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132474);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-9363",
    "CVE-2018-9517",
    "CVE-2018-10853",
    "CVE-2018-14625",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16871",
    "CVE-2018-16884",
    "CVE-2018-18281",
    "CVE-2018-20856",
    "CVE-2019-1125",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-9506",
    "CVE-2019-10126",
    "CVE-2019-11085",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11811",
    "CVE-2019-11833",
    "CVE-2019-14821",
    "CVE-2019-14835"
  );
  script_bugtraq_id(
    105120,
    105761,
    106253,
    106478,
    106565,
    107782,
    107910,
    108076,
    108113,
    108286,
    108372,
    108410,
    108488,
    108521,
    108547,
    108817
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0247)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in the Linux kernel's NFS41+ subsystem.
    NFS41+ shares mounted in different network namespaces at
    the same time can make bc_svc_process() use wrong back-
    channel IDs and cause a use-after-free vulnerability.
    Thus a malicious container user can cause a host kernel
    memory corruption and a system panic. Due to the nature
    of the flaw, privilege escalation cannot be fully ruled
    out. (CVE-2018-16884)

  - Insufficient input validation in Kernel Mode Driver in
    Intel(R) i915 Graphics for Linux before version 5.0 may
    allow an authenticated user to potentially enable
    escalation of privilege via local access.
    (CVE-2019-11085)

  - A flaw was found in the Linux kernel's NFS
    implementation, all versions 3.x and all versions 4.x up
    to 4.20. An attacker, who is able to mount an exported
    NFS filesystem, is able to trigger a null pointer
    dereference by using an invalid NFS sequence. This can
    panic the machine and deny access to the NFS server. Any
    outstanding disk writes to the NFS server will be lost.
    (CVE-2018-16871)

  - An issue was discovered in the Linux kernel before
    5.0.4. There is a use-after-free upon attempted read
    access to /proc/ioports after the ipmi_si module is
    removed, related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and
    drivers/char/ipmi/ipmi_si_port_io.c. (CVE-2019-11811)

  - A flaw was found in the way Linux kernel KVM hypervisor
    before 4.18 emulated instructions such as
    sgdt/sidt/fxsave/fxrstor. It did not check current
    privilege(CPL) level while emulating unprivileged
    instructions. An unprivileged guest user/process could
    use this flaw to potentially escalate privileges inside
    guest. (CVE-2018-10853)

  - A flaw was found in the Linux Kernel where an attacker
    may be able to have an uncontrolled read to kernel-
    memory from within a vm guest. A race condition between
    connect() and close() function may allow an attacker
    using the AF_VSOCK protocol to gather a 4 byte
    information leak or possibly intercept or corrupt
    AF_VSOCK messages destined to other clients.
    (CVE-2018-14625)

  - drivers/infiniband/core/ucma.c in the Linux kernel
    through 4.17.11 allows ucma_leave_multicast to access a
    certain data structure after a cleanup step in
    ucma_process_join, which allows attackers to cause a
    denial of service (use-after-free). (CVE-2018-14734)

  - arch/x86/kernel/paravirt.c in the Linux kernel before
    4.18.1 mishandles certain indirect calls, which makes it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtual guests. (CVE-2018-15594)

  - Since Linux kernel version 3.2, the mremap() syscall
    performs TLB flushes after dropping pagetable locks. If
    a syscall such as ftruncate() removes entries from the
    pagetables of a task that is in the middle of mremap(),
    a stale TLB entry can remain for a short time that
    permits access to a physical page after it has been
    released back to the page allocator and reused. This is
    fixed in the following kernel versions: 4.9.135,
    4.14.78, 4.18.16, 4.19. (CVE-2018-18281)

  - An issue was discovered in the Linux kernel before
    4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain
    error case is mishandled. (CVE-2018-20856)

  - In the hidp_process_report in bluetooth, there is an
    integer overflow. This could lead to an out of bounds
    write with no additional execution privileges needed.
    User interaction is not needed for exploitation.
    Product: Android Versions: Android kernel Android ID:
    A-65853588 References: Upstream kernel. (CVE-2018-9363)

  - In pppol2tp_connect, there is possible memory corruption
    due to a use after free. This could lead to local
    escalation of privilege with System execution privileges
    needed. User interaction is not needed for exploitation.
    Product: Android. Versions: Android kernel. Android ID:
    A-38159931. (CVE-2018-9517)

  - A flaw was found in the Linux kernel. A heap based
    buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead
    to memory corruption and possibly other consequences.
    (CVE-2019-10126)

  - An information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - The coredump implementation in the Linux kernel before
    5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs,
    which allows local users to obtain sensitive
    information, cause a denial of service, or possibly have
    unspecified other impact by triggering a race condition
    with mmget_not_zero or get_task_mm calls. This is
    related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and
    drivers/infiniband/core/uverbs_main.c. (CVE-2019-11599)

  - An issue was discovered in the Linux kernel before
    5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in
    megasas_alloc_cmds() in
    drivers/scsi/megaraid/megaraid_sas_base.c. This causes a
    Denial of Service, related to a use-after-free.
    (CVE-2019-11810)

  - fs/ext4/extents.c in the Linux kernel through 5.1.2 does
    not zero out the unused memory region in the extent tree
    block, which might allow local users to obtain sensitive
    information by reading uninitialized data in the
    filesystem. (CVE-2019-11833)

  - An out-of-bounds access issue was found in the Linux
    kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO
    write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write
    indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged
    host user or process with access to '/dev/kvm' device
    could use this flaw to crash the host kernel, resulting
    in a denial of service or potentially escalating
    privileges on the system. (CVE-2019-14821)

  - A buffer overflow flaw was found, in versions from
    2.6.34 to 5.2.x, in the way Linux kernel's vhost
    functionality that translates virtqueue buffers to IOVs,
    logged the buffer descriptors during migration. A
    privileged guest user able to pass descriptors with
    invalid length to the host when migration is underway,
    could use this flaw to increase their privileges on the
    host. (CVE-2019-14835)

  - A heap address information leak while using
    L2CAP_GET_CONF_OPT was discovered in the Linux kernel
    before 5.1-rc1. (CVE-2019-3459)

  - A heap data infoleak in multiple locations including
    L2CAP_PARSE_CONF_RSP was found in the Linux kernel
    before 5.1-rc1. (CVE-2019-3460)

  - A flaw that allowed an attacker to corrupt memory and
    possibly escalate privileges was found in the mwifiex
    kernel module while connecting to a malicious wireless
    network. (CVE-2019-3846)

  - A flaw was found in the Linux kernel's vfio interface
    implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio
    driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it may
    cause a system memory exhaustion and thus a denial of
    service (DoS). Versions 3.10, 4.14 and 4.18 are
    vulnerable. (CVE-2019-3882)

  - An infinite loop issue was found in the vhost_net kernel
    module in Linux Kernel up to and including v5.1-rc6,
    while handling incoming packets in handle_rx(). It could
    occur if one end sends packets faster than the other end
    can process them. A guest user, maybe remote one, could
    use this flaw to stall the vhost_net kernel thread,
    resulting in a DoS scenario. (CVE-2019-3900)

  - The mincore() implementation in mm/mincore.c in the
    Linux kernel through 4.19.13 allowed local attackers to
    observe page cache access patterns of other processes on
    the same system, potentially allowing sniffing of secret
    information. (Fixing this affects the output of the
    fincore program.) Limited remote exploitation may be
    possible, as demonstrated by latency differences in
    accessing public files from an Apache HTTP Server.
    (CVE-2019-5489)

  - The Bluetooth BR/EDR specification up to and including
    version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from influencing
    the key length negotiation. This allows practical brute-
    force attacks (aka KNOB) that can decrypt traffic and
    inject arbitrary ciphertext without the victim noticing.
    (CVE-2019-9506)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0247");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "bpftool-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-core-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "perf-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "python-perf-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite",
    "python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.144.ge0a5bc9.lite"
  ],
  "CGSL MAIN 5.05": [
    "bpftool-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "perf-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "python-perf-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad",
    "python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.12.141.g47e8cad"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
