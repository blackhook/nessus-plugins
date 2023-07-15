#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0333-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96903);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2004-0230", "CVE-2012-6704", "CVE-2013-4312", "CVE-2015-1350", "CVE-2015-7513", "CVE-2015-7833", "CVE-2015-8956", "CVE-2015-8962", "CVE-2015-8964", "CVE-2016-0823", "CVE-2016-10088", "CVE-2016-1583", "CVE-2016-2187", "CVE-2016-2189", "CVE-2016-3841", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5829", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7117", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7916", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-8633", "CVE-2016-8646", "CVE-2016-9555", "CVE-2016-9576", "CVE-2016-9685", "CVE-2016-9756", "CVE-2016-9793", "CVE-2017-5551");
  script_bugtraq_id(10183);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:0333-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 LTSS kernel was updated to receive
various security and bugfixes. This is the last planned LTSS kernel
update for the SUSE Linux Enterprise Server 11 SP2 LTSS. The following
security bugs were fixed :

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2004-0230: TCP, when using a large Window Size, made
    it easier for remote attackers to guess sequence numbers
    and cause a denial of service (connection loss) to
    persistent TCP connections by repeatedly injecting a TCP
    RST packet, especially in protocols that use long-lived
    connections, such as BGP (bnc#969340).

  - CVE-2016-8632: The tipc_msg_build function in
    net/tipc/msg.c in the Linux kernel did not validate the
    relationship between the minimum fragment length and the
    maximum packet size, which allowed local users to gain
    privileges or cause a denial of service (heap-based
    buffer overflow) by leveraging the CAP_NET_ADMIN
    capability (bnc#1008831).

  - CVE-2016-8399: An out of bounds read in the ping
    protocol handler could have lead to information
    disclosure (bsc#1014746).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option
    (bnc#1013531).

  - CVE-2012-6704: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1) SO_SNDBUF or
    (2) SO_RCVBUF option (bnc#1013542).

  - CVE-2016-9756: arch/x86/kvm/emulate.c in the Linux
    kernel did not properly initialize Code Segment (CS) in
    certain error cases, which allowed local users to obtain
    sensitive information from kernel stack memory via a
    crafted application (bnc#1013038).

  - CVE-2016-3841: The IPv6 stack in the Linux kernel
    mishandled options data, which allowed local users to
    gain privileges or cause a denial of service
    (use-after-free and system crash) via a crafted sendmsg
    system call (bnc#992566).

  - CVE-2016-9685: Multiple memory leaks in error paths in
    fs/xfs/xfs_attr_list.c in the Linux kernel allowed local
    users to cause a denial of service (memory consumption)
    via crafted XFS filesystem operations (bnc#1012832).

  - CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x
    provides an incomplete set of requirements for setattr
    operations that underspecified removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bnc#914939).

  - CVE-2015-8962: Double free vulnerability in the
    sg_common_write function in drivers/scsi/sg.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (memory corruption and system
    crash) by detaching a device during an SG_IO ioctl call
    (bnc#1010501).

  - CVE-2016-9555: The sctp_sf_ootb function in
    net/sctp/sm_statefuns.c in the Linux kernel lacked
    chunk-length checking for the first chunk, which allowed
    remote attackers to cause a denial of service
    (out-of-bounds slab access) or possibly have unspecified
    other impact via crafted SCTP data (bnc#1011685).

  - CVE-2016-7910: Use-after-free vulnerability in the
    disk_seqf_stop function in block/genhd.c in the Linux
    kernel allowed local users to gain privileges by
    leveraging the execution of a certain stop operation
    even if the corresponding start operation had failed
    (bnc#1010716).

  - CVE-2016-7911: Race condition in the get_task_ioprio
    function in block/ioprio.c in the Linux kernel allowed
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted ioprio_get system
    call (bnc#1010711).

  - CVE-2015-8964: The tty_set_termios_ldisc function in
    drivers/tty/tty_ldisc.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a tty data structure (bnc#1010507).

  - CVE-2016-7916: Race condition in the environ_read
    function in fs/proc/base.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a /proc/*/environ file during a
    process-setup time interval in which
    environment-variable copying is incomplete
    (bnc#1010467).

  - CVE-2016-8646: The hash_accept function in
    crypto/algif_hash.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) by attempting
    to trigger use of in-kernel hash algorithms for a socket
    that has received zero bytes of data (bnc#1010150).

  - CVE-2016-8633: drivers/firewire/net.c in the Linux
    kernel before 4.8.7, in certain unusual hardware
    configurations, allowed remote attackers to execute
    arbitrary code via crafted fragmented packets
    (bnc#1008833).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel used an
    incorrect buffer size for certain timeout data, which
    allowed local users to cause a denial of service (stack
    memory corruption and panic) by reading the /proc/keys
    file (bnc#1004517).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserves the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bnc#995968).

  - CVE-2017-5551: The filesystem implementation in the
    Linux kernel preserves the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions. This CVE tracks the
    fix for the tmpfs filesystem. (bsc#1021258).

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077).

  - CVE-2016-0823: The pagemap_open function in
    fs/proc/task_mmu.c in the Linux kernel allowed local
    users to obtain sensitive physical-address information
    by reading a pagemap file, aka Android internal bug
    25739721 (bnc#994759).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability
    (bnc#991608).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from kernel heap memory by leveraging
    in-container root access to provide a crafted offset
    value that leads to crossing a ruleset blob boundary
    (bsc#986365).

  - CVE-2015-7513: arch/x86/kvm/x86.c in the Linux kernel
    did not reset the PIT counter values during state
    restoration, which allowed guest OS users to cause a
    denial of service (divide-by-zero error and host OS
    crash) via a zero value, related to the
    kvm_vm_ioctl_set_pit and kvm_vm_ioctl_set_pit2 functions
    (bnc#960689).

  - CVE-2013-4312: The Linux kernel allowed local users to
    bypass file-descriptor limits and cause a denial of
    service (memory consumption) by sending each descriptor
    over a UNIX socket before closing it, related to
    net/unix/af_unix.c and net/unix/garbage.c (bnc#839104).

  - CVE-2016-4997: The compat IPT_SO_SET_REPLACE and
    IP6T_SO_SET_REPLACE setsockopt implementations in the
    netfilter subsystem in the Linux kernel allow local
    users to gain privileges or cause a denial of service
    (memory corruption) by leveraging in-container root
    access to provide a crafted offset value that triggers
    an unintended decrement (bnc#986362).

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allow
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572).

  - CVE-2016-4470: The key_reject_and_link function in
    security/keys/key.c in the Linux kernel did not ensure
    that a certain data structure is initialized, which
    allowed local users to cause a denial of service (system
    crash) via vectors involving a crafted keyctl request2
    command (bnc#984755).

  - CVE-2016-5244: The rds_inc_info_copy function in
    net/rds/recv.c in the Linux kernel did not initialize a
    certain structure member, which allowed remote attackers
    to obtain sensitive information from kernel stack memory
    by reading an RDS message (bnc#983213).

  - CVE-2016-1583: The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (stack memory consumption) via vectors involving crafted
    mmap calls for /proc pathnames, leading to recursive
    pagefault handling (bnc#983143).

  - CVE-2016-4913: The get_rock_ridge_filename function in
    fs/isofs/rock.c in the Linux kernel mishandled NM (aka
    alternate name) entries containing \0 characters, which
    allowed local users to obtain sensitive information from
    kernel memory or possibly have unspecified other impact
    via a crafted isofs filesystem (bnc#980725).

  - CVE-2016-4580: The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel did not
    properly initialize a certain data structure, which
    allowed attackers to obtain sensitive information from
    kernel stack memory via an X.25 Call Request
    (bnc#981267).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2015-7833: The usbvision driver in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (panic) via a nonzero bInterfaceNumber value
    in a USB device descriptor (bnc#950998).

  - CVE-2016-2187: The gtco_probe function in
    drivers/input/tablet/gtco.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#971944).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-4485: The llc_cmsg_rcv function in
    net/llc/af_llc.c in the Linux kernel did not initialize
    a certain data structure, which allowed attackers to
    obtain sensitive information from kernel stack memory by
    reading a message (bnc#978821).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1009443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=835175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=839104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=863873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=874145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=896484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=922947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=989261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=992566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=993890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2004-0230/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2012-6704/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4312/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1350/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7513/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7833/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8956/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8962/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8964/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0823/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10088/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1583/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2187/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2189/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3841/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4482/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4485/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4565/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4578/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4580/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4913/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4997/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4998/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5829/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6480/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6828/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7042/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7097/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7117/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7425/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7910/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7916/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8399/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8632/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8633/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8646/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9555/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9685/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9756/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9793/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5551/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170333-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e5f107f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-kernel-12961=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-kernel-12961=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.53.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.53.1")) flag++;


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
