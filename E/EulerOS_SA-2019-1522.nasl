#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124975);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-4387",
    "CVE-2014-3183",
    "CVE-2014-8709",
    "CVE-2014-9728",
    "CVE-2015-1465",
    "CVE-2015-8816",
    "CVE-2016-1237",
    "CVE-2016-2067",
    "CVE-2016-3138",
    "CVE-2016-3156",
    "CVE-2016-8636",
    "CVE-2016-9084",
    "CVE-2016-9576",
    "CVE-2016-9604",
    "CVE-2017-8924",
    "CVE-2017-18270",
    "CVE-2018-1065",
    "CVE-2018-6927",
    "CVE-2018-12896",
    "CVE-2018-18281"
  );
  script_bugtraq_id(
    62696,
    69766,
    70965,
    72435,
    74964
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1522)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - drivers/gpu/msm/kgsl.c in the MSM graphics driver (aka
    GPU driver) for the Linux kernel 3.x, as used in
    Qualcomm Innovation Center (QuIC) Android contributions
    for MSM devices and other products, mishandles the
    KGSL_MEMFLAGS_GPUREADONLY flag, which allows attackers
    to gain privileges by leveraging accidental read-write
    mappings, aka Qualcomm internal bug
    CR988993.(CVE-2016-2067i1/4%0

  - Integer overflow in the mem_check_range function in
    drivers/infiniband/sw/rxe/rxe_mr.c in the Linux kernel
    before 4.9.10 allows local users to cause a denial of
    service (memory corruption), obtain sensitive
    information from kernel memory, or possibly have
    unspecified other impact via a write or read request
    involving the 'RDMA protocol over infiniband' (aka Soft
    RoCE) technology.(CVE-2016-8636i1/4%0

  - Heap-based buffer overflow in the
    logi_dj_ll_raw_request function in
    drivers/hid/hid-logitech-dj.c in the Linux kernel
    before 3.16.2 allows physically proximate attackers to
    cause a denial of service (system crash) or possibly
    execute arbitrary code via a crafted device that
    specifies a large report size for an LED
    report.(CVE-2014-3183i1/4%0

  - The futex_requeue function in kernel/futex.c in the
    Linux kernel, before 4.14.15, might allow attackers to
    cause a denial of service (integer overflow) or
    possibly have unspecified other impacts by triggering a
    negative wake or requeue value. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is
    unlikely.(CVE-2018-6927i1/4%0

  - The hub_activate function in drivers/usb/core/hub.c in
    the Linux kernel before 4.3.5 does not properly
    maintain a hub-interface data structure, which allows
    physically proximate attackers to cause a denial of
    service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device.(CVE-2015-8816i1/4%0

  - It was found that the blk_rq_map_user_iov() function in
    the Linux kernel's block device implementation did not
    properly restrict the type of iterator, which could
    allow a local attacker to read or write to arbitrary
    kernel memory locations or cause a denial of service
    (use-after-free) by leveraging write access to a
    /dev/sg device.(CVE-2016-9576i1/4%0

  - A security flaw was found in the Linux kernel's
    networking subsystem that destroying the network
    interface with huge number of ipv4 addresses assigned
    keeps 'rtnl_lock' spinlock for a very long time (up to
    hour). This blocks many network-related operations,
    including creation of new incoming ssh connections.The
    problem is especially important for containers, as the
    container owner has enough permissions to trigger this
    and block a network access on a whole host, outside the
    container.(CVE-2016-3156i1/4%0

  - The edge_bulk_in_callback function in
    drivers/usb/serial/io_ti.c in the Linux kernel allows
    local users to obtain sensitive information (in the
    dmesg ringbuffer and syslog) from uninitialized kernel
    memory by using a crafted USB device (posing as an
    io_ti USB serial device) to trigger an integer
    underflow.(CVE-2017-8924i1/4%0

  - The IPv4 implementation in the Linux kernel before
    3.18.8 does not properly consider the length of the
    Read-Copy Update (RCU) grace period for redirecting
    lookups in the absence of caching, which allows remote
    attackers to cause a denial of service (memory
    consumption or system crash) via a flood of
    packets.(CVE-2015-1465i1/4%0

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9728i1/4%0

  - net/ipv6/ip6_output.c in the Linux kernel through
    3.11.4 does not properly determine the need for UDP
    Fragmentation Offload (UFO) processing of small packets
    after the UFO queueing of a large packet, which allows
    remote attackers to cause a denial of service (memory
    corruption and system crash) or possibly have
    unspecified other impact via network traffic that
    triggers a large response packet.(CVE-2013-4387i1/4%0

  - It was found that nfsd is missing permissions check
    when setting ACL on files, this may allow a local users
    to gain access to any file by setting a crafted
    ACL.(CVE-2016-1237i1/4%0

  - In the Linux kernel before 4.13.5, a local user could
    create keyrings for other users via keyctl commands,
    setting unwanted defaults or causing a denial of
    service.(CVE-2017-18270i1/4%0

  - An issue was discovered in the Linux kernel where an
    integer overflow in kernel/time/posix-timers.c in the
    POSIX timer code is caused by the way the overrun
    accounting works. Depending on interval and expiry time
    values, the overrun can be larger than INT_MAX, but the
    accounting is int based. This basically makes the
    accounting values, which are visible to user space via
    timer_getoverrun(2) and siginfo::si_overrun,
    random.(CVE-2018-12896i1/4%0

  - Since Linux kernel version 3.2, the mremap() syscall
    performs TLB flushes after dropping pagetable locks. If
    a syscall such as ftruncate() removes entries from the
    pagetables of a task that is in the middle of mremap(),
    a stale TLB entry can remain for a short time that
    permits access to a physical page after it has been
    released back to the page allocator and reused. This is
    fixed in the following kernel versions: 4.9.135,
    4.14.78, 4.18.16, 4.19.(CVE-2018-18281i1/4%0

  - The netfilter subsystem in the Linux kernel through
    4.15.7 mishandles the case of a rule blob that contains
    a jump but lacks a user-defined chain, which allows
    local users to cause a denial of service (NULL pointer
    dereference) by leveraging the CAP_NET_RAW or
    CAP_NET_ADMIN capability, related to arpt_do_table in
    net/ipv4/netfilter/arp_tables.c, ipt_do_table in
    net/ipv4/netfilter/ip_tables.c, and ip6t_do_table in
    net/ipv6/netfilter/ip6_tables.c.(CVE-2018-1065i1/4%0

  - The use of a kzalloc with an integer multiplication
    allowed an integer overflow condition to be reached in
    vfio_pci_intrs.c. This combined with CVE-2016-9083 may
    allow an attacker to craft an attack and use
    unallocated memory, potentially crashing the
    machine.(CVE-2016-9084i1/4%0

  - The acm_probe function in drivers/usb/class/cdc-acm.c
    in the Linux kernel before 4.5.1 allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and system crash) via a USB device
    without both a control and a data endpoint
    descriptor.(CVE-2016-3138i1/4%0

  - It was discovered that root can gain direct access to
    an internal keyring, such as '.dns_resolver' in RHEL-7
    or '.builtin_trusted_keys' upstream, by joining it as
    its session keyring. This allows root to bypass module
    signature verification by adding a new public key of
    its own devising to the keyring.(CVE-2016-9604i1/4%0

  - An information leak flaw was found in the Linux
    kernel's IEEE 802.11 wireless networking
    implementation. When software encryption was used, a
    remote attacker could use this flaw to leak up to 8
    bytes of plaintext.(CVE-2014-8709i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d7a6c1c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2067");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
