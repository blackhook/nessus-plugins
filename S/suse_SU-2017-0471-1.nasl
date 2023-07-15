#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0471-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97205);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9904", "CVE-2015-8956", "CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-4470", "CVE-2016-4998", "CVE-2016-5696", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7913", "CVE-2016-7914", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-8658", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2017:0471-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to 3.12.61 to
receive various security and bugfixes. The following feature was
implemented :

  - The ext2 filesystem got reenabled and supported to allow
    support for 'XIP' (Execute In Place) (FATE#320805). The
    following security bugs were fixed :

  - CVE-2017-5551: The tmpfs filesystem implementation in
    the Linux kernel preserved the setgid bit during a
    setxattr call, which allowed local users to gain group
    privileges by leveraging the existence of a setgid
    program with restrictions on execute permissions
    (bsc#1021258).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserved the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bnc#995968).

  - CVE-2017-2583: A Linux kernel built with the
    Kernel-based Virtual Machine (CONFIG_KVM) support was
    vulnerable to an incorrect segment selector(SS) value
    error. A user/process inside guest could have used this
    flaw to crash the guest resulting in DoS or potentially
    escalate their privileges inside guest. (bsc#1020602).

  - CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt (bnc#1019851).

  - CVE-2016-10088: The sg implementation in the Linux
    kernel did not properly restrict write operations in
    situations where the KERNEL_DS option is set, which
    allowed local users to read or write to arbitrary kernel
    memory locations or cause a denial of service
    (use-after-free) by leveraging access to a /dev/sg
    device, related to block/bsg.c and drivers/scsi/sg.c.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2016-9576 (bnc#1017710).

  - CVE-2016-8645: The TCP stack in the Linux kernel
    mishandled skb truncation, which allowed local users to
    cause a denial of service (system crash) via a crafted
    application that made sendto system calls, related to
    net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c
    (bnc#1009969).

  - CVE-2016-8399: An elevation of privilege vulnerability
    in the kernel networking subsystem could enable a local
    malicious application to execute arbitrary code within
    the context of the kernel. This issue is rated as
    Moderate because it first requires compromising a
    privileged process and current compiler optimizations
    restrict access to the vulnerable code. Product:
    Android. Versions: Kernel-3.10, Kernel-3.18. Android ID:
    A-31349935 (bnc#1014746).

  - CVE-2016-9806: Race condition in the netlink_dump
    function in net/netlink/af_netlink.c in the Linux kernel
    allowed local users to cause a denial of service (double
    free) or possibly have unspecified other impact via a
    crafted application that made sendmsg system calls,
    leading to a free operation associated with a new dump
    that started earlier than anticipated (bnc#1013540).

  - CVE-2016-9756: arch/x86/kvm/emulate.c in the Linux
    kernel did not properly initialize Code Segment (CS) in
    certain error cases, which allowed local users to obtain
    sensitive information from kernel stack memory via a
    crafted application (bnc#1013038).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option
    (bnc#1013531).

  - CVE-2016-7910: Use-after-free vulnerability in the
    disk_seqf_stop function in block/genhd.c in the Linux
    kernel allowed local users to gain privileges by
    leveraging the execution of a certain stop operation
    even if the corresponding start operation had failed
    (bnc#1010716).

  - CVE-2015-8962: Double free vulnerability in the
    sg_common_write function in drivers/scsi/sg.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (memory corruption and system
    crash) by detaching a device during an SG_IO ioctl call
    (bnc#1010501).

  - CVE-2016-7913: The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (use-after-free) via vectors involving
    omission of the firmware name from a certain data
    structure (bnc#1010478).

  - CVE-2016-7911: Race condition in the get_task_ioprio
    function in block/ioprio.c in the Linux kernel allowed
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted ioprio_get system
    call (bnc#1010711).

  - CVE-2015-8964: The tty_set_termios_ldisc function in
    drivers/tty/tty_ldisc.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a tty data structure (bnc#1010507).

  - CVE-2015-8963: Race condition in kernel/events/core.c in
    the Linux kernel allowed local users to gain privileges
    or cause a denial of service (use-after-free) by
    leveraging incorrect handling of an swevent data
    structure during a CPU unplug operation (bnc#1010502).

  - CVE-2016-7914: The assoc_array_insert_into_terminal_node
    function in lib/assoc_array.c in the Linux kernel did
    not check whether a slot is a leaf, which allowed local
    users to obtain sensitive information from kernel memory
    or cause a denial of service (invalid pointer
    dereference and out-of-bounds read) via an application
    that uses associative-array data structures, as
    demonstrated by the keyutils test suite (bnc#1010475).

  - CVE-2016-8633: drivers/firewire/net.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via crafted fragmented packets (bnc#1008833).

  - CVE-2016-9083: drivers/vfio/pci/vfio_pci.c in the Linux
    kernel allowed local users to bypass integer overflow
    checks, and cause a denial of service (memory
    corruption) or have unspecified other impact, by
    leveraging access to a vfio PCI device file for a
    VFIO_DEVICE_SET_IRQS ioctl call, aka a 'state machine
    confusion bug (bnc#1007197).

  - CVE-2016-9084: drivers/vfio/pci/vfio_pci_intrs.c in the
    Linux kernel misused the kzalloc function, which allowed
    local users to cause a denial of service (integer
    overflow) or have unspecified other impact by leveraging
    access to a vfio PCI device file (bnc#1007197).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel uses an
    incorrect buffer size for certain timeout data, which
    allowed local users to cause a denial of service (stack
    memory corruption and panic) by reading the /proc/keys
    file (bnc#1004517).

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

  - CVE-2016-8658: Stack-based buffer overflow in the
    brcmf_cfg80211_start_ap function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a long SSID Information
    Element in a command to a Netlink socket (bnc#1004462).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    by using an ABORT_TASK command to abort a device write
    operation (bnc#994748).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for remote attackers to
    hijack TCP sessions via a blind in-window attack
    (bnc#989152).

  - CVE-2016-6130: Race condition in the sclp_ctl_ioctl_sccb
    function in drivers/s390/char/sclp_ctl.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory by changing a certain
    length value, aka a 'double fetch' vulnerability
    (bnc#987542).

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
    (bnc#986362 bnc#986365).

  - CVE-2016-5828: The start_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms mishandled transactional state, which
    allowed local users to cause a denial of service
    (invalid process state or TM Bad Thing exception, and
    system crash) or possibly have unspecified other impact
    by starting and suspending a transaction before an exec
    system call (bnc#986569).

  - CVE-2014-9904: The snd_compress_check_input function in
    sound/core/compress_offload.c in the ALSA subsystem in
    the Linux kernel did not properly check for an integer
    overflow, which allowed local users to cause a denial of
    service (insufficient memory allocation) or possibly
    have unspecified other impact via a crafted
    SNDRV_COMPRESS_SET_PARAMS ioctl call (bnc#986811).

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

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1008979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1009969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010612"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012422"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013540"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1016482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1019300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1019851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=881008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=985978"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=986941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=987542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=987565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=987576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990384"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=993392"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=998795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9904/"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8963/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8964/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10088/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4998/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5696/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5828/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5829/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6327/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-7913/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7914/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8399/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8633/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8645/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9083/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9084/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-9806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2583/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2584/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5551/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170471-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7188b37b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-247=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-247=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2017-247=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_66-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_66-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_66-default-1-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_66-xen-1-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.61-52.66.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.61-52.66.1")) flag++;


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
