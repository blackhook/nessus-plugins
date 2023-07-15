#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0004. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127146);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2013-2888",
    "CVE-2013-2889",
    "CVE-2013-2892",
    "CVE-2013-2930",
    "CVE-2013-4127",
    "CVE-2013-4162",
    "CVE-2013-4163",
    "CVE-2013-4343",
    "CVE-2013-4348",
    "CVE-2013-4350",
    "CVE-2013-4387",
    "CVE-2013-4563",
    "CVE-2013-4579",
    "CVE-2013-4587",
    "CVE-2013-6367",
    "CVE-2013-6368",
    "CVE-2013-6376",
    "CVE-2013-6378",
    "CVE-2013-6380",
    "CVE-2013-6382",
    "CVE-2013-7026",
    "CVE-2013-7266",
    "CVE-2013-7267",
    "CVE-2013-7268",
    "CVE-2013-7269",
    "CVE-2013-7270",
    "CVE-2013-7271",
    "CVE-2014-0049",
    "CVE-2014-0055",
    "CVE-2014-0069",
    "CVE-2014-0077",
    "CVE-2014-0100",
    "CVE-2014-0101",
    "CVE-2014-0102",
    "CVE-2014-0131",
    "CVE-2014-0155",
    "CVE-2014-1438",
    "CVE-2014-1690",
    "CVE-2014-2309",
    "CVE-2014-2523",
    "CVE-2014-3122",
    "CVE-2014-3601",
    "CVE-2014-3610",
    "CVE-2014-4014",
    "CVE-2014-6416",
    "CVE-2014-8480",
    "CVE-2014-8989",
    "CVE-2015-2041",
    "CVE-2015-2042",
    "CVE-2015-7550",
    "CVE-2016-3713",
    "CVE-2016-8399",
    "CVE-2017-6353",
    "CVE-2017-7184",
    "CVE-2017-7541",
    "CVE-2017-7542",
    "CVE-2017-7558",
    "CVE-2017-11176",
    "CVE-2017-14106",
    "CVE-2017-1000111",
    "CVE-2017-1000112"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2019-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has kernel packages installed that are affected by multiple
vulnerabilities:

  - Multiple array index errors in drivers/hid/hid-core.c in
    the Human Interface Device (HID) subsystem in the Linux
    kernel through 3.11 allow physically proximate attackers
    to execute arbitrary code or cause a denial of service
    (heap memory corruption) via a crafted device that
    provides an invalid Report ID. (CVE-2013-2888)

  - drivers/hid/hid-zpff.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_ZEROPLUS is enabled, allows physically
    proximate attackers to cause a denial of service (heap-
    based out-of-bounds write) via a crafted device.
    (CVE-2013-2889)

  - drivers/hid/hid-pl.c in the Human Interface Device (HID)
    subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_PANTHERLORD is enabled, allows physically
    proximate attackers to cause a denial of service (heap-
    based out-of-bounds write) via a crafted device.
    (CVE-2013-2892)

  - The perf_trace_event_perm function in
    kernel/trace/trace_event_perf.c in the Linux kernel
    before 3.12.2 does not properly restrict access to the
    perf subsystem, which allows local users to enable
    function tracing via a crafted application.
    (CVE-2013-2930)

  - Use-after-free vulnerability in the
    vhost_net_set_backend function in drivers/vhost/net.c in
    the Linux kernel through 3.10.3 allows local users to
    cause a denial of service (OOPS and system crash) via
    vectors involving powering on a virtual machine.
    (CVE-2013-4127)

  - The udp_v6_push_pending_frames function in
    net/ipv6/udp.c in the IPv6 implementation in the Linux
    kernel through 3.10.3 makes an incorrect function call
    for pending data, which allows local users to cause a
    denial of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call. (CVE-2013-4162)

  - The ip6_append_data_mtu function in
    net/ipv6/ip6_output.c in the IPv6 implementation in the
    Linux kernel through 3.10.3 does not properly maintain
    information about whether the IPV6_MTU setsockopt option
    had been specified, which allows local users to cause a
    denial of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call. (CVE-2013-4163)

  - Use-after-free vulnerability in drivers/net/tun.c in the
    Linux kernel through 3.11.1 allows local users to gain
    privileges by leveraging the CAP_NET_ADMIN capability
    and providing an invalid tuntap interface name in a
    TUNSETIFF ioctl call. (CVE-2013-4343)

  - The skb_flow_dissect function in
    net/core/flow_dissector.c in the Linux kernel through
    3.12 allows remote attackers to cause a denial of
    service (infinite loop) via a small value in the IHL
    field of a packet with IPIP encapsulation.
    (CVE-2013-4348)

  - The IPv6 SCTP implementation in net/sctp/ipv6.c in the
    Linux kernel through 3.11.1 uses data structures and
    function calls that do not trigger an intended
    configuration of IPsec encryption, which allows remote
    attackers to obtain sensitive information by sniffing
    the network. (CVE-2013-4350)

  - net/ipv6/ip6_output.c in the Linux kernel through 3.11.4
    does not properly determine the need for UDP
    Fragmentation Offload (UFO) processing of small packets
    after the UFO queueing of a large packet, which allows
    remote attackers to cause a denial of service (memory
    corruption and system crash) or possibly have
    unspecified other impact via network traffic that
    triggers a large response packet. (CVE-2013-4387)

  - The udp6_ufo_fragment function in net/ipv6/udp_offload.c
    in the Linux kernel through 3.12, when UDP Fragmentation
    Offload (UFO) is enabled, does not properly perform a
    certain size comparison before inserting a fragment
    header, which allows remote attackers to cause a denial
    of service (panic) via a large IPv6 UDP packet, as
    demonstrated by use of the Token Bucket Filter (TBF)
    queueing discipline. (CVE-2013-4563)

  - The ath9k_htc_set_bssid_mask function in
    drivers/net/wireless/ath/ath9k/htc_drv_main.c in the
    Linux kernel through 3.12 uses a BSSID masking approach
    to determine the set of MAC addresses on which a Wi-Fi
    device is listening, which allows remote attackers to
    discover the original MAC address after spoofing by
    sending a series of packets to MAC addresses with
    certain bit manipulations. (CVE-2013-4579)

  - Array index error in the kvm_vm_ioctl_create_vcpu
    function in virt/kvm/kvm_main.c in the KVM subsystem in
    the Linux kernel through 3.12.5 allows local users to
    gain privileges via a large id value. (CVE-2013-4587)

  - The apic_get_tmcct function in arch/x86/kvm/lapic.c in
    the KVM subsystem in the Linux kernel through 3.12.5
    allows guest OS users to cause a denial of service
    (divide-by-zero error and host OS crash) via crafted
    modifications of the TMICT value. (CVE-2013-6367)

  - The KVM subsystem in the Linux kernel through 3.12.5
    allows local users to gain privileges or cause a denial
    of service (system crash) via a VAPIC synchronization
    operation involving a page-end address. (CVE-2013-6368)

  - The recalculate_apic_map function in
    arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
    kernel through 3.12.5 allows guest OS users to cause a
    denial of service (host OS crash) via a crafted ICR
    write operation in x2apic mode. (CVE-2013-6376)

  - The lbs_debugfs_write function in
    drivers/net/wireless/libertas/debugfs.c in the Linux
    kernel through 3.12.1 allows local users to cause a
    denial of service (OOPS) by leveraging root privileges
    for a zero-length write operation. (CVE-2013-6378)

  - The aac_send_raw_srb function in
    drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 3.12.1 does not properly validate a certain size
    value, which allows local users to cause a denial of
    service (invalid pointer dereference) or possibly have
    unspecified other impact via an FSACTL_SEND_RAW_SRB
    ioctl call that triggers a crafted SRB command.
    (CVE-2013-6380)

  - Multiple buffer underflows in the XFS implementation in
    the Linux kernel through 3.12.1 allow local users to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact by leveraging the
    CAP_SYS_ADMIN capability for a (1)
    XFS_IOC_ATTRLIST_BY_HANDLE or (2)
    XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted
    length value, related to the xfs_attrlist_by_handle
    function in fs/xfs/xfs_ioctl.c and the
    xfs_compat_attrlist_by_handle function in
    fs/xfs/xfs_ioctl32.c. (CVE-2013-6382)

  - Multiple race conditions in ipc/shm.c in the Linux
    kernel before 3.12.2 allow local users to cause a denial
    of service (use-after-free and system crash) or possibly
    have unspecified other impact via a crafted application
    that uses shmctl IPC_RMID operations in conjunction with
    other shm system calls. (CVE-2013-7026)

  - The mISDN_sock_recvmsg function in
    drivers/isdn/mISDN/socket.c in the Linux kernel before
    3.12.4 does not ensure that a certain length value is
    consistent with the size of an associated data
    structure, which allows local users to obtain sensitive
    information from kernel memory via a (1) recvfrom, (2)
    recvmmsg, or (3) recvmsg system call. (CVE-2013-7266)

  - The atalk_recvmsg function in net/appletalk/ddp.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (CVE-2013-7267)

  - The ipx_recvmsg function in net/ipx/af_ipx.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (CVE-2013-7268)

  - The nr_recvmsg function in net/netrom/af_netrom.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (CVE-2013-7269)

  - The packet_recvmsg function in net/packet/af_packet.c in
    the Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (CVE-2013-7270)

  - The x25_recvmsg function in net/x25/af_x25.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (CVE-2013-7271)

  - Buffer overflow in the complete_emulated_mmio function
    in arch/x86/kvm/x86.c in the Linux kernel before 3.13.6
    allows guest OS users to execute arbitrary code on the
    host OS by leveraging a loop that triggers an invalid
    memory copy affecting certain cancel_work_item data.
    (CVE-2014-0049)

  - The get_rx_bufs function in drivers/vhost/net.c in the
    vhost-net subsystem in the Linux kernel package before
    2.6.32-431.11.2 on Red Hat Enterprise Linux (RHEL) 6
    does not properly handle vhost_get_vq_desc errors, which
    allows guest OS users to cause a denial of service (host
    OS crash) via unspecified vectors. (CVE-2014-0055)

  - The cifs_iovec_write function in fs/cifs/file.c in the
    Linux kernel through 3.13.5 does not properly handle
    uncached write operations that copy fewer than the
    requested number of bytes, which allows local users to
    obtain sensitive information from kernel memory, cause a
    denial of service (memory corruption and system crash),
    or possibly gain privileges via a writev system call
    with a crafted pointer. (CVE-2014-0069)

  - drivers/vhost/net.c in the Linux kernel before 3.13.10,
    when mergeable buffers are disabled, does not properly
    validate packet lengths, which allows guest OS users to
    cause a denial of service (memory corruption and host OS
    crash) or possibly gain privileges on the host OS via
    crafted packets, related to the handle_rx and
    get_rx_bufs functions. (CVE-2014-0077)

  - Race condition in the inet_frag_intern function in
    net/ipv4/inet_fragment.c in the Linux kernel through
    3.13.6 allows remote attackers to cause a denial of
    service (use-after-free error) or possibly have
    unspecified other impact via a large series of
    fragmented ICMP Echo Request packets to a system with a
    heavy CPU load. (CVE-2014-0100)

  - A flaw was found in the way the Linux kernel processed
    an authenticated COOKIE_ECHO chunk during the
    initialization of an SCTP connection. A remote attacker
    could use this flaw to crash the system by initiating a
    specially crafted SCTP handshake in order to trigger a
    NULL pointer dereference on the system. (CVE-2014-0101)

  - The keyring_detect_cycle_iterator function in
    security/keys/keyring.c in the Linux kernel through
    3.13.6 does not properly determine whether keyrings are
    identical, which allows local users to cause a denial of
    service (OOPS) via crafted keyctl commands.
    (CVE-2014-0102)

  - Use-after-free vulnerability in the skb_segment function
    in net/core/skbuff.c in the Linux kernel through 3.13.6
    allows attackers to obtain sensitive information from
    kernel memory by leveraging the absence of a certain
    orphaning operation. (CVE-2014-0131)

  - The ioapic_deliver function in virt/kvm/ioapic.c in the
    Linux kernel through 3.14.1 does not properly validate
    the kvm_irq_delivery_to_apic return value, which allows
    guest OS users to cause a denial of service (host OS
    crash) via a crafted entry in the redirection table of
    an I/O APIC. NOTE: the affected code was moved to the
    ioapic_service function before the vulnerability was
    announced. (CVE-2014-0155)

  - The restore_fpu_checking function in
    arch/x86/include/asm/fpu-internal.h in the Linux kernel
    before 3.12.8 on the AMD K7 and K8 platforms does not
    clear pending exceptions before proceeding to an EMMS
    instruction, which allows local users to cause a denial
    of service (task kill) or possibly gain privileges via a
    crafted application. (CVE-2014-1438)

  - The help function in net/netfilter/nf_nat_irc.c in the
    Linux kernel before 3.12.8 allows remote attackers to
    obtain sensitive information from kernel memory by
    establishing an IRC DCC session in which incorrect
    packet data is transmitted during use of the NAT mangle
    feature. (CVE-2014-1690)

  - The ip6_route_add function in net/ipv6/route.c in the
    Linux kernel through 3.13.6 does not properly count the
    addition of routes, which allows remote attackers to
    cause a denial of service (memory consumption) via a
    flood of ICMPv6 Router Advertisement packets.
    (CVE-2014-2309)

  - net/netfilter/nf_conntrack_proto_dccp.c in the Linux
    kernel through 3.13.6 uses a DCCP header pointer
    incorrectly, which allows remote attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via a DCCP packet that triggers a call to
    the (1) dccp_new, (2) dccp_packet, or (3) dccp_error
    function. (CVE-2014-2523)

  - It was found that the try_to_unmap_cluster() function in
    the Linux kernel's Memory Managment subsystem did not
    properly handle page locking in certain cases, which
    could potentially trigger the BUG_ON() macro in the
    mlock_vma_page() function. A local, unprivileged user
    could use this flaw to crash the system. (CVE-2014-3122)

  - A flaw was found in the way the Linux kernel's
    kvm_iommu_map_pages() function handled IOMMU mapping
    failures. A privileged user in a guest with an assigned
    host device could use this flaw to crash the host.
    (CVE-2014-3601)

  - It was found that KVM's Write to Model Specific Register
    (WRMSR) instruction emulation would write non-canonical
    values passed in by the guest to certain MSRs in the
    host's context. A privileged guest user could use this
    flaw to crash the host. (CVE-2014-3610)

  - The capabilities implementation in the Linux kernel
    before 3.14.8 does not properly consider that namespaces
    are inapplicable to inodes, which allows local users to
    bypass intended chmod restrictions by first creating a
    user namespace, as demonstrated by setting the setgid
    bit on a file with group ownership of root.
    (CVE-2014-4014)

  - Buffer overflow in net/ceph/auth_x.c in Ceph, as used in
    the Linux kernel before 3.16.3, allows remote attackers
    to cause a denial of service (memory corruption and
    panic) or possibly have unspecified other impact via a
    long unencrypted auth ticket. (CVE-2014-6416)

  - The instruction decoder in arch/x86/kvm/emulate.c in the
    KVM subsystem in the Linux kernel before 3.18-rc2 lacks
    intended decoder-table flags for certain RIP-relative
    instructions, which allows guest OS users to cause a
    denial of service (NULL pointer dereference and host OS
    crash) via a crafted application. (CVE-2014-8480)

  - The Linux kernel through 3.17.4 does not properly
    restrict dropping of supplemental group memberships in
    certain namespace scenarios, which allows local users to
    bypass intended file permissions by leveraging a POSIX
    ACL containing an entry for the group category that is
    more restrictive than the entry for the other category,
    aka a negative groups issue, related to
    kernel/groups.c, kernel/uid16.c, and
    kernel/user_namespace.c. (CVE-2014-8989)

  - net/llc/sysctl_net_llc.c in the Linux kernel before 3.19
    uses an incorrect data type in a sysctl table, which
    allows local users to obtain potentially sensitive
    information from kernel memory or possibly have
    unspecified other impact by accessing a sysctl entry.
    (CVE-2015-2041)

  - net/rds/sysctl.c in the Linux kernel before 3.19 uses an
    incorrect data type in a sysctl table, which allows
    local users to obtain potentially sensitive information
    from kernel memory or possibly have unspecified other
    impact by accessing a sysctl entry. (CVE-2015-2042)

  - A NULL-pointer dereference flaw was found in the kernel,
    which is caused by a race between revoking a user-type
    key and reading from it. The issue could be triggered by
    an unprivileged user with a local account, causing the
    kernel to crash (denial of service). (CVE-2015-7550)

  - The msr_mtrr_valid function in arch/x86/kvm/mtrr.c in
    the Linux kernel before 4.6.1 supports MSR 0x2f8, which
    allows guest OS users to read or write to the
    kvm_arch_vcpu data structure, and consequently obtain
    sensitive information or cause a denial of service
    (system crash), via a crafted ioctl call.
    (CVE-2016-3713)

  - A flaw was found in the Linux networking subsystem where
    a local attacker with CAP_NET_ADMIN capabilities could
    cause an out-of-bounds memory access by creating a
    smaller-than-expected ICMP header and sending to its
    destination via sendto(). (CVE-2016-8399)

  - A race condition issue was found in the way the raw
    packet socket implementation in the Linux kernel
    networking subsystem handled synchronization. A local
    user able to open a raw packet socket (requires the
    CAP_NET_RAW capability) could use this to waste
    resources in the kernel's ring buffer or possibly cause
    an out-of-bounds read on the heap leading to a system
    crash. (CVE-2017-1000111)

  - An exploitable memory corruption flaw was found in the
    Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data()
    when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw
    can be exploited to gain root privileges.
    (CVE-2017-1000112)

  - A use-after-free flaw was found in the Netlink
    functionality of the Linux kernel networking subsystem.
    Due to the insufficient cleanup in the mq_notify
    function, a local attacker could potentially use this
    flaw to escalate their privileges on the system.
    (CVE-2017-11176)

  - A divide-by-zero vulnerability was found in the
    __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of
    service. (CVE-2017-14106)

  - It was found that the code in net/sctp/socket.c in the
    Linux kernel through 4.10.1 does not properly restrict
    association peel-off operations during certain wait
    states, which allows local users to cause a denial of
    service (invalid unlock and double free) via a
    multithreaded application. This vulnerability was
    introduced by CVE-2017-5986 fix (commit 2dcab5984841).
    (CVE-2017-6353)

  - Out-of-bounds kernel heap access vulnerability was found
    in xfrm, kernel's IP framework for transforming packets.
    An error dealing with netlink messages from an
    unprivileged user leads to arbitrary read/write and
    privilege escalation. (CVE-2017-7184)

  - Kernel memory corruption due to a buffer overflow was
    found in brcmf_cfg80211_mgmt_tx() function in Linux
    kernels from v3.9-rc1 to v4.13-rc1. The vulnerability
    can be triggered by sending a crafted NL80211_CMD_FRAME
    packet via netlink. This flaw is unlikely to be
    triggered remotely as certain userspace code is needed
    for this. An unprivileged local user could use this flaw
    to induce kernel memory corruption on the system,
    leading to a crash. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out, although
    it is unlikely. (CVE-2017-7541)

  - An integer overflow vulnerability in
    ip6_find_1stfragopt() function was found. A local
    attacker that has privileges (of CAP_NET_RAW) to open
    raw socket can cause an infinite loop inside the
    ip6_find_1stfragopt() function. (CVE-2017-7542)

  - A kernel data leak due to an out-of-bound read was found
    in the Linux kernel in inet_diag_msg_sctp{,l}addr_fill()
    and sctp_get_sctp_info() functions present since version
    4.7-rc1 through version 4.13. A data leak happens when
    these functions fill in sockaddr data structures used to
    export socket's diagnostic information. As a result, up
    to 100 bytes of the slab data could be leaked to a
    userspace. (CVE-2017-7558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2523");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "kernel-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-abi-whitelists-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-debug-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-debug-debuginfo-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-debug-devel-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-debuginfo-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-debuginfo-common-x86_64-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-devel-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-doc-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-headers-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-tools-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-tools-debuginfo-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-tools-libs-3.10.0-693.5.2.el7.cgsl2058",
    "kernel-tools-libs-devel-3.10.0-693.5.2.el7.cgsl2058",
    "perf-3.10.0-693.5.2.el7.cgsl2058",
    "perf-debuginfo-3.10.0-693.5.2.el7.cgsl2058",
    "python-perf-3.10.0-693.5.2.el7.cgsl2058",
    "python-perf-debuginfo-3.10.0-693.5.2.el7.cgsl2058"
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
