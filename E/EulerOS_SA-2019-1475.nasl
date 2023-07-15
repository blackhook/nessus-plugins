#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124799);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4348",
    "CVE-2013-4350",
    "CVE-2013-4387",
    "CVE-2013-4470",
    "CVE-2013-4511",
    "CVE-2013-4563",
    "CVE-2013-4579",
    "CVE-2013-4587",
    "CVE-2013-6367",
    "CVE-2013-6368",
    "CVE-2013-6376",
    "CVE-2013-6378",
    "CVE-2013-6380",
    "CVE-2013-6382",
    "CVE-2013-6383",
    "CVE-2013-6431",
    "CVE-2013-6763",
    "CVE-2013-7026",
    "CVE-2013-7027",
    "CVE-2013-7263",
    "CVE-2013-7264"
  );
  script_bugtraq_id(
    62405,
    62696,
    63359,
    63512,
    63536,
    63702,
    63707,
    63743,
    63886,
    63887,
    63888,
    63889,
    64013,
    64137,
    64270,
    64291,
    64312,
    64319,
    64328,
    64685,
    64686
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1475)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The skb_flow_dissect function in
    net/core/flow_dissector.c in the Linux kernel through
    3.12 allows remote attackers to cause a denial of
    service (infinite loop) via a small value in the IHL
    field of a packet with IPIP
    encapsulation.(CVE-2013-4348)

  - The IPv6 SCTP implementation in net/sctp/ipv6.c in the
    Linux kernel through 3.11.1 uses data structures and
    function calls that do not trigger an intended
    configuration of IPsec encryption, which allows remote
    attackers to obtain sensitive information by sniffing
    the network.(CVE-2013-4350)

  - net/ipv6/ip6_output.c in the Linux kernel through
    3.11.4 does not properly determine the need for UDP
    Fragmentation Offload (UFO) processing of small packets
    after the UFO queueing of a large packet, which allows
    remote attackers to cause a denial of service (memory
    corruption and system crash) or possibly have
    unspecified other impact via network traffic that
    triggers a large response packet.(CVE-2013-4387)

  - The Linux kernel before 3.12, when UDP Fragmentation
    Offload (UFO) is enabled, does not properly initialize
    certain data structures, which allows local users to
    cause a denial of service (memory corruption and system
    crash) or possibly gain privileges via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call and sends both short and long
    packets, related to the ip_ufo_append_data function in
    net/ipv4/ip_output.c and the ip6_ufo_append_data
    function in net/ipv6/ip6_output.c.(CVE-2013-4470)

  - Multiple integer overflows in Alchemy LCD frame-buffer
    drivers in the Linux kernel before 3.12 allow local
    users to create a read-write memory mapping for the
    entirety of kernel memory, and consequently gain
    privileges, via crafted mmap operations, related to the
    (1) au1100fb_fb_mmap function in
    drivers/video/au1100fb.c and the (2) au1200fb_fb_mmap
    function in drivers/video/au1200fb.c.(CVE-2013-4511)

  - The udp6_ufo_fragment function in
    net/ipv6/udp_offload.c in the Linux kernel through
    3.12, when UDP Fragmentation Offload (UFO) is enabled,
    does not properly perform a certain size comparison
    before inserting a fragment header, which allows remote
    attackers to cause a denial of service (panic) via a
    large IPv6 UDP packet, as demonstrated by use of the
    Token Bucket Filter (TBF) queueing
    discipline.(CVE-2013-4563)

  - The ath9k_htc_set_bssid_mask function in
    drivers/net/wireless/ath/ath9k/htc_drv_main.c in the
    Linux kernel through 3.12 uses a BSSID masking approach
    to determine the set of MAC addresses on which a Wi-Fi
    device is listening, which allows remote attackers to
    discover the original MAC address after spoofing by
    sending a series of packets to MAC addresses with
    certain bit manipulations.(CVE-2013-4579)

  - Array index error in the kvm_vm_ioctl_create_vcpu
    function in virt/kvm/kvm_main.c in the KVM subsystem in
    the Linux kernel through 3.12.5 allows local users to
    gain privileges via a large id value.(CVE-2013-4587)

  - The apic_get_tmcct function in arch/x86/kvm/lapic.c in
    the KVM subsystem in the Linux kernel through 3.12.5
    allows guest OS users to cause a denial of service
    (divide-by-zero error and host OS crash) via crafted
    modifications of the TMICT value.(CVE-2013-6367)

  - The KVM subsystem in the Linux kernel through 3.12.5
    allows local users to gain privileges or cause a denial
    of service (system crash) via a VAPIC synchronization
    operation involving a page-end address.(CVE-2013-6368)

  - The recalculate_apic_map function in
    arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
    kernel through 3.12.5 allows guest OS users to cause a
    denial of service (host OS crash) via a crafted ICR
    write operation in x2apic mode.(CVE-2013-6376)

  - The lbs_debugfs_write function in
    drivers/net/wireless/libertas/debugfs.c in the Linux
    kernel through 3.12.1 allows local users to cause a
    denial of service (OOPS) by leveraging root privileges
    for a zero-length write operation.(CVE-2013-6378)

  - The aac_send_raw_srb function in
    drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 3.12.1 does not properly validate a certain
    size value, which allows local users to cause a denial
    of service (invalid pointer dereference) or possibly
    have unspecified other impact via an
    FSACTL_SEND_RAW_SRB ioctl call that triggers a crafted
    SRB command.(CVE-2013-6380)

  - Multiple buffer underflows in the XFS implementation in
    the Linux kernel through 3.12.1 allow local users to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact by leveraging
    the CAP_SYS_ADMIN capability for a (1)
    XFS_IOC_ATTRLIST_BY_HANDLE or (2)
    XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted
    length value, related to the xfs_attrlist_by_handle
    function in fs/xfs/xfs_ioctl.c and the
    xfs_compat_attrlist_by_handle function in
    fs/xfs/xfs_ioctl32.c.(CVE-2013-6382)

  - The aac_compat_ioctl function in
    drivers/scsi/aacraid/linit.c in the Linux kernel before
    3.11.8 does not require the CAP_SYS_RAWIO capability,
    which allows local users to bypass intended access
    restrictions via a crafted ioctl call.(CVE-2013-6383)

  - The fib6_add function in net/ipv6/ip6_fib.c in the
    Linux kernel before 3.11.5 does not properly implement
    error-code encoding, which allows local users to cause
    a denial of service (NULL pointer dereference and
    system crash) by leveraging the CAP_NET_ADMIN
    capability for an IPv6 SIOCADDRT ioctl
    call.(CVE-2013-6431)

  - The uio_mmap_physical function in drivers/uio/uio.c in
    the Linux kernel before 3.12 does not validate the size
    of a memory block, which allows local users to cause a
    denial of service (memory corruption) or possibly gain
    privileges via crafted mmap operations, a different
    vulnerability than CVE-2013-4511.(CVE-2013-6763)

  - Multiple race conditions in ipc/shm.c in the Linux
    kernel before 3.12.2 allow local users to cause a
    denial of service (use-after-free and system crash) or
    possibly have unspecified other impact via a crafted
    application that uses shmctl IPC_RMID operations in
    conjunction with other shm system calls.(CVE-2013-7026)

  - The ieee80211_radiotap_iterator_init function in
    net/wireless/radiotap.c in the Linux kernel before
    3.11.7 does not check whether a frame contains any data
    outside of the header, which might allow attackers to
    cause a denial of service (buffer over-read) via a
    crafted header.(CVE-2013-7027)

  - The Linux kernel before 3.12.4 updates certain length
    values before ensuring that associated data structures
    have been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call, related to net/ipv4/ping.c, net/ipv4/raw.c,
    net/ipv4/udp.c, net/ipv6/raw.c, and
    net/ipv6/udp.c.(CVE-2013-7263)

  - The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in
    the Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call.(CVE-2013-7264)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1475
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83a4c385");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
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
