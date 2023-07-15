#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124821);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-9754",
    "CVE-2016-9793",
    "CVE-2016-9794",
    "CVE-2016-9806",
    "CVE-2017-1000111",
    "CVE-2017-1000112",
    "CVE-2017-1000251",
    "CVE-2017-1000252",
    "CVE-2017-1000364",
    "CVE-2017-1000365",
    "CVE-2017-1000370",
    "CVE-2017-1000410",
    "CVE-2017-10661",
    "CVE-2017-10810",
    "CVE-2017-10911",
    "CVE-2017-11176",
    "CVE-2017-11473",
    "CVE-2017-11600",
    "CVE-2017-12153",
    "CVE-2017-12154",
    "CVE-2017-12188"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1498)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An integer overflow vulnerability was found in the
    ring_buffer_resize() calculations in which a privileged
    user can adjust the size of the ringbuffer message
    size. These calculations can create an issue where the
    kernel memory allocator will not allocate the correct
    count of pages yet expect them to be usable. This can
    lead to the ftrace() output to appear to corrupt kernel
    memory and possibly be used for privileged escalation
    or more likely kernel panic.(CVE-2016-9754)

  - A flaw was found in the Linux kernel's implementation
    of setsockopt for the SO_{SND|RCV}BUFFORCE setsockopt()
    system call. Users with non-namespace CAP_NET_ADMIN are
    able to trigger this call and create a situation in
    which the sockets sendbuff data size could be negative.
    This could adversely affect memory allocations and
    create situations where the system could crash or cause
    memory corruption.(CVE-2016-9793)

  - A use-after-free vulnerability was found in ALSA pcm
    layer, which allows local users to cause a denial of
    service, memory corruption, or possibly other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-9794)

  - A double free vulnerability was found in netlink_dump,
    which could cause a denial of service or possibly other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-9806)

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets are
    implemented in the Linux kernel networking subsystem
    handling synchronization. A local user able to open a
    raw packet socket (requires the CAP_NET_RAW capability)
    can use this issue to crash the
    system.(CVE-2017-1000111)

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root
    privileges.(CVE-2017-1000112)

  - A stack buffer overflow flaw was found in the way the
    Bluetooth subsystem of the Linux kernel processed
    pending L2CAP configuration responses from a client. On
    systems with the stack protection feature enabled in
    the kernel (CONFIG_CC_STACKPROTECTOR=y, which is
    enabled on all architectures other than s390x and
    ppc64le), an unauthenticated attacker able to initiate
    a connection to a system via Bluetooth could use this
    flaw to crash the system. Due to the nature of the
    stack protection feature, code execution cannot be
    fully ruled out, although we believe it is unlikely. On
    systems without the stack protection feature (ppc64le
    the Bluetooth modules are not built on s390x), an
    unauthenticated attacker able to initiate a connection
    to a system via Bluetooth could use this flaw to
    remotely execute arbitrary code on the system with ring
    0 (kernel) privileges.(CVE-2017-1000251)

  - A reachable assertion failure flaw was found in the
    Linux kernel built with KVM virtualisation(CONFIG_KVM)
    support with Virtual Function I/O feature (CONFIG_VFIO)
    enabled. This failure could occur if a malicious guest
    device sent a virtual interrupt (guest IRQ) with a
    larger (i1/4z1024) index value.(CVE-2017-1000252)

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on
    the system. This is a kernel-side mitigation which
    increases the stack guard gap size from one page to 1
    MiB to make successful exploitation of this issue more
    difficult.(CVE-2017-1000364)

  - The Linux Kernel imposes a size restriction on the
    arguments and environmental strings passed through
    RLIMIT_STACK/RLIMIT_INFINITY, but does not take the
    argument and environment pointers into account, which
    allows attackers to bypass this
    limitation.(CVE-2017-1000365)

  - The offset2lib patch as used in the Linux Kernel
    contains a vulnerability that allows a PIE binary to be
    execve()'ed with 1GB of arguments or environmental
    strings then the stack occupies the address 0x80000000
    and the PIE binary is mapped above 0x40000000
    nullifying the protection of the offset2lib patch. This
    affects Linux Kernel version 4.11.5 and earlier. This
    is a different issue than CVE-2017-1000371. This issue
    appears to be limited to i386 based
    systems.(CVE-2017-1000370)

  - A flaw was found in the processing of incoming L2CAP
    bluetooth commands. Uninitialized stack variables can
    be sent to an attacker leaking data in kernel address
    space.(CVE-2017-1000410)

  - A race condition was found in the Linux kernel before
    version 4.11-rc1 in 'fs/timerfd.c' file which allows a
    local user to cause a kernel list corruption or
    use-after-free via simultaneous operations with a file
    descriptor which leverage improper 'might_cancel'
    queuing. An unprivileged local user could use this flaw
    to cause a denial of service of the system. Due to the
    nature of the flaw, privilege escalation cannot be
    fully ruled out, although we believe it is
    unlikely.(CVE-2017-10661)

  - Memory leak in the virtio_gpu_object_create function in
    drivers/gpu/drm/virtio/virtgpu_object.c in the Linux
    kernel through 4.11.8 allows attackers to cause a
    denial of service (memory consumption) by triggering
    object-initialization failures.(CVE-2017-10810)

  - The make_response function in
    drivers/block/xen-blkback/blkback.c in the Linux kernel
    before 4.11.8 allows guest OS users to obtain sensitive
    information from host OS (or other guest OS) kernel
    memory by leveraging the copying of uninitialized
    padding fields in Xen block-interface response
    structures, aka XSA-216.(CVE-2017-10911)

  - A use-after-free flaw was found in the Netlink
    functionality of the Linux kernel networking subsystem.
    Due to the insufficient cleanup in the mq_notify
    function, a local attacker could potentially use this
    flaw to escalate their privileges on the
    system.(CVE-2017-11176)

  - Buffer overflow in the mp_override_legacy_irq()
    function in arch/x86/kernel/acpi/boot.c in the Linux
    kernel through 4.12.2 allows local users to gain
    privileges via a crafted ACPI table.(CVE-2017-11473)

  - The xfrm_migrate() function in the
    net/xfrm/xfrm_policy.c file in the Linux kernel built
    with CONFIG_XFRM_MIGRATE does not verify if the dir
    parameter is less than XFRM_POLICY_MAX. This allows a
    local attacker to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact by sending a XFRM_MSG_MIGRATE netlink
    message. This flaw is present in the Linux kernel since
    an introduction of XFRM_MSG_MIGRATE in 2.6.21-rc1, up
    to 4.13-rc3.(CVE-2017-11600)

  - A security flaw was discovered in
    nl80211_set_rekey_data() function in the Linux kernel
    since v3.1-rc1 through v4.13. This function does not
    check whether the required attributes are present in a
    netlink request. This request can be issued by a user
    with CAP_NET_ADMIN privilege and may result in NULL
    dereference and a system crash.(CVE-2017-12153)

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization (nVMX) feature
    enabled (nested=1), is vulnerable to a crash due to
    disabled external interrupts. As L2 guest could access
    (r/w) hardware CR8 register of the host(L0). In a
    nested visualization setup, L2 guest user could use
    this flaw to potentially crash the host(L0) resulting
    in DoS.(CVE-2017-12154)

  - The Linux kernel built with the KVM visualization
    support (CONFIG_KVM), with nested visualization(nVMX)
    feature enabled (nested=1), was vulnerable to a stack
    buffer overflow issue. The vulnerability could occur
    while traversing guest page table entries to resolve
    guest virtual address(gva). An L1 guest could use this
    flaw to crash the host kernel resulting in denial of
    service (DoS) or potentially execute arbitrary code on
    the host to gain privileges on the
    system.(CVE-2017-12188)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1498
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e495b75");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000251");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
