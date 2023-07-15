#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2920-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104374);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-9004", "CVE-2016-10229", "CVE-2016-10277", "CVE-2016-9604", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11176", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12192", "CVE-2017-12762", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15649", "CVE-2017-2647", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7482", "CVE-2017-7487", "CVE-2017-7518", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8106", "CVE-2017-8831", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2017:2920-1) (KRACK) (Stack Clash)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 GA LTS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2017-15649: net/packet/af_packet.c in the Linux
    kernel allowed local users to gain privileges via
    crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind) that
    leads to a use-after-free, a different vulnerability
    than CVE-2017-6346 (bnc#1064388).

  - CVE-2015-9004: kernel/events/core.c in the Linux kernel
    mishandled counter grouping, which allowed local users
    to gain privileges via a crafted application, related to
    the perf_pmu_register and perf_event_open functions
    (bnc#1037306).

  - CVE-2016-10229: udp.c in the Linux kernel allowed remote
    attackers to execute arbitrary code via UDP traffic that
    triggers an unsafe second checksum calculation during
    execution of a recv system call with the MSG_PEEK flag
    (bnc#1032268).

  - CVE-2016-9604: The handling of keyrings starting with
    '.' in KEYCTL_JOIN_SESSION_KEYRING, which could have
    allowed local users to manipulate privileged keyrings,
    was fixed (bsc#1035576)

  - CVE-2017-1000363: Linux drivers/char/lp.c Out-of-Bounds
    Write. Due to a missing bounds check, and the fact that
    parport_ptr integer is static, a 'secure boot' kernel
    command line adversary (can happen due to bootloader
    vulns, e.g. Google Nexus 6's CVE-2016-10277, where due
    to a vulnerability the adversary has partial control
    over the command line) can overflow the parport_nr array
    in the following code, by appending many (>LP_NO)
    'lp=none' arguments to the command line (bnc#1039456).

  - CVE-2017-1000365: The Linux Kernel imposes a size
    restriction on the arguments and environmental strings
    passed through RLIMIT_STACK/RLIM_INFINITY (1/4 of the
    size), but did not take the argument and environment
    pointers into account, which allowed attackers to bypass
    this limitation. (bnc#1039354).

  - CVE-2017-1000380: sound/core/timer.c in the Linux kernel
    is vulnerable to a data race in the ALSA /dev/snd/timer
    driver resulting in local users being able to read
    information belonging to other users, i.e.,
    uninitialized memory contents may be disclosed when a
    read and an ioctl happen at the same time (bnc#1044125).

  - CVE-2017-10661: Race condition in fs/timerfd.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (list corruption or
    use-after-free) via simultaneous file-descriptor
    operations that leverage improper might_cancel queueing
    (bnc#1053152).

  - CVE-2017-11176: The mq_notify function in the Linux
    kernel did not set the sock pointer to NULL upon entry
    into the retry logic. During a user-space close of a
    Netlink socket, it allowed attackers to cause a denial
    of service (use-after-free) or possibly have unspecified
    other impact (bnc#1048275).

  - CVE-2017-12153: A security flaw was discovered in the
    nl80211_set_rekey_data() function in
    net/wireless/nl80211.c in the Linux kernel This function
    did not check whether the required attributes are
    present in a Netlink request. This request can be issued
    by a user with the CAP_NET_ADMIN capability and may
    result in a NULL pointer dereference and system crash
    (bnc#1058410).

  - CVE-2017-12154: The prepare_vmcs02 function in
    arch/x86/kvm/vmx.c in the Linux kernel did not ensure
    that the 'CR8-load exiting' and 'CR8-store exiting' L0
    vmcs02 controls exist in cases where L1 omits the 'use
    TPR shadow' vmcs12 control, which allowed KVM L2 guest
    OS users to obtain read and write access to the hardware
    CR8 register (bnc#1058507).

  - CVE-2017-12762: In /drivers/isdn/i4l/isdn_net.c: A
    user-controlled buffer is copied into a local buffer of
    constant size using strcpy without a length check which
    can cause a buffer overflow. (bnc#1053148).

  - CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2)
    allowed reinstallation of the Group Temporal Key (GTK)
    during the group key handshake, allowing an attacker
    within radio range to replay frames from access points
    to clients (bnc#1063667).

  - CVE-2017-14051: An integer overflow in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash) by leveraging root access
    (bnc#1056588).

  - CVE-2017-14106: The tcp_disconnect function in
    net/ipv4/tcp.c in the Linux kernel allowed local users
    to cause a denial of service (__tcp_select_window
    divide-by-zero error and system crash) by triggering a
    disconnect within a certain tcp_recvmsg code path
    (bnc#1056982).

  - CVE-2017-14140: The move_pages system call in
    mm/migrate.c in the Linux kernel doesn't check the
    effective uid of the target process, enabling a local
    attacker to learn the memory layout of a setuid
    executable despite ASLR (bnc#1057179).

  - CVE-2017-15265: Use-after-free vulnerability in the
    Linux kernel allowed local users to have unspecified
    impact via vectors related to /dev/snd/seq
    (bnc#1062520).

  - CVE-2017-15274: security/keys/keyctl.c in the Linux
    kernel did not consider the case of a NULL payload in
    conjunction with a nonzero length value, which allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted add_key or keyctl
    system call, a different vulnerability than
    CVE-2017-12192 (bnc#1045327).

  - CVE-2017-2647: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash)
    via vectors involving a NULL value for a certain match
    field, related to the keyring_search_iterator function
    in keyring.c (bnc#1030593).

  - CVE-2017-6951: The keyring_search_aux function in
    security/keys/keyring.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a request_key system call for
    the 'dead' type (bnc#1029850).

  - CVE-2017-7482: A potential memory corruption was fixed
    in decoding of krb5 principals in the kernels kerberos
    handling. (bnc#1046107).

  - CVE-2017-7487: The ipxitf_ioctl function in
    net/ipx/af_ipx.c in the Linux kernel mishandled
    reference counts, which allowed local users to cause a
    denial of service (use-after-free) or possibly have
    unspecified other impact via a failed SIOCGIFADDR ioctl
    call for an IPX interface (bnc#1038879).

  - CVE-2017-7518: The Linux kernel was vulnerable to an
    incorrect debug exception(#DB) error. It could occur
    while emulating a syscall instruction and potentially
    lead to guest privilege escalation. (bsc#1045922).

  - CVE-2017-7541: The brcmf_cfg80211_mgmt_tx function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (buffer overflow and system crash) or
    possibly gain privileges via a crafted NL80211_CMD_FRAME
    Netlink packet (bnc#1049645).

  - CVE-2017-7542: The ip6_find_1stfragopt function in
    net/ipv6/output_core.c in the Linux kernel allowed local
    users to cause a denial of service (integer overflow and
    infinite loop) by leveraging the ability to open a raw
    socket (bnc#1049882).

  - CVE-2017-7889: The mm subsystem in the Linux kernel did
    not properly enforce the CONFIG_STRICT_DEVMEM protection
    mechanism, which allowed local users to read or write to
    kernel memory locations in the first megabyte (and
    bypass slab-allocation access restrictions) via an
    application that opens the /dev/mem file, related to
    arch/x86/mm/init.c and drivers/char/mem.c (bnc#1034405).

  - CVE-2017-8106: The handle_invept function in
    arch/x86/kvm/vmx.c in the Linux kernel 3.12 allowed
    privileged KVM guest OS users to cause a denial of
    service (NULL pointer dereference and host OS crash) via
    a single-context INVEPT instruction with a NULL EPT
    pointer (bnc#1035877).

  - CVE-2017-8831: The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds array access) or possibly have
    unspecified other impact by changing a certain
    sequence-number value, aka a 'double fetch'
    vulnerability (bnc#1037994).

  - CVE-2017-8890: The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allowed attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call (bnc#1038544).

  - CVE-2017-8924: The edge_bulk_in_callback function in
    drivers/usb/serial/io_ti.c in the Linux kernel allowed
    local users to obtain sensitive information (in the
    dmesg ringbuffer and syslog) from uninitialized kernel
    memory by using a crafted USB device (posing as an io_ti
    USB serial device) to trigger an integer underflow
    (bnc#1037182 bsc#1038982).

  - CVE-2017-8925: The omninet_open function in
    drivers/usb/serial/omninet.c in the Linux kernel allowed
    local users to cause a denial of service (tty
    exhaustion) by leveraging reference count mishandling
    (bnc#1037183 bsc#1038981).

  - CVE-2017-9074: The IPv6 fragmentation implementation in
    the Linux kernel did not consider that the nexthdr field
    may be associated with an invalid option, which allowed
    local users to cause a denial of service (out-of-bounds
    read and BUG) or possibly have unspecified other impact
    via crafted socket and send system calls (bnc#1039882).

  - CVE-2017-9075: The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1039883).

  - CVE-2017-9076: The dccp_v6_request_recv_sock function in
    net/dccp/ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1039885).

  - CVE-2017-9077: The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel mishandled
    inheritance, which allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    crafted system calls, a related issue to CVE-2017-8890
    (bnc#1040069).

  - CVE-2017-9242: The __ip6_append_data function in
    net/ipv6/ip6_output.c in the Linux kernel is too late in
    checking whether an overwrite of an skb data structure
    may occur, which allowed local users to cause a denial
    of service (system crash) via crafted system calls
    (bnc#1041431).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1029850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=938162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=985562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-9004/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10229/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9604/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000363/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000365/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000380/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10661/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11176/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12153/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12154/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12762/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13080/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14051/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14106/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14140/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15265/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15274/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2647/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6951/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7482/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7487/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7518/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7541/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7542/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7889/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8106/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8831/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8890/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8924/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8925/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9074/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9075/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9076/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9077/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9242/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172920-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7fae168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1808=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2017-1808=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_101-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_101-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_101-default-1-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_101-xen-1-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.61-52.101.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.61-52.101.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
