#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0040-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105685);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000251", "CVE-2017-11600", "CVE-2017-12192", "CVE-2017-13080", "CVE-2017-13167", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14340", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16534", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16538", "CVE-2017-16649", "CVE-2017-16939", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7472", "CVE-2017-8824");
  script_xref(name:"IAVA", value:"2017-A-0310");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2018:0040-1) (BlueBorne) (KRACK) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive
various security and bugfixes. This update adds mitigations for
various side channel attacks against modern CPUs that could disclose
content of otherwise unreadable memory (bnc#1068032).

  - CVE-2017-5753: Local attackers on systems with modern
    CPUs featuring deep instruction pipelining could use
    attacker controllable speculative execution over code
    patterns in the Linux Kernel to leak content from
    otherwise not readable memory in the same address space,
    allowing retrieval of passwords, cryptographic keys and
    other secrets. This problem is mitigated by adding
    speculative fencing on affected code paths throughout
    the Linux kernel.

  - CVE-2017-5715: Local attackers on systems with modern
    CPUs featuring branch prediction could use mispredicted
    branches to speculatively execute code patterns that in
    turn could be made to leak other non-readable content in
    the same address space, an attack similar to
    CVE-2017-5753. This problem is mitigated by disabling
    predictive branches, depending on CPU architecture
    either by firmware updates and/or fixes in the
    user-kernel privilege boundaries. Please contact your
    CPU / hardware vendor for potential microcode or BIOS
    updates needed for this fix. As this feature can have a
    performance impact, it can be disabled using the
    'nospec' kernel commandline option.

  - CVE-2017-5754: Local attackers on systems with modern
    CPUs featuring deep instruction pipelining could use
    code patterns in userspace to speculative executive code
    that would read otherwise read protected memory, an
    attack similar to CVE-2017-5753. This problem is
    mitigated by unmapping the Linux Kernel from the user
    address space during user code execution, following a
    approach called 'KAISER'. The terms used here are
    'KAISER' / 'Kernel Address Isolation' and 'PTI' / 'Page
    Table Isolation'. This feature is disabled on unaffected
    architectures. This feature can be enabled / disabled by
    the 'pti=[on|off|auto]' or 'nopti' commandline options.
    The following security bugs were fixed :

  - CVE-2017-1000251: The native Bluetooth stack in the
    Linux Kernel (BlueZ) was vulnerable to a stack overflow
    vulnerability in the processing of L2CAP configuration
    responses resulting in Remote code execution in kernel
    space (bnc#1057389).

  - CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux
    kernel did not ensure that the dir value of
    xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which
    allowed local users to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact via an XFRM_MSG_MIGRATE xfrm Netlink
    message (bnc#1050231).

  - CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2)
    allowed reinstallation of the Group Temporal Key (GTK)
    during the group key handshake, allowing an attacker
    within radio range to replay frames from access points
    to clients (bnc#1063667).

  - CVE-2017-13167: An elevation of privilege vulnerability
    in the kernel sound timer was fixed. (bnc#1072876).

  - CVE-2017-14106: The tcp_disconnect function in
    net/ipv4/tcp.c in the Linux kernel allowed local users
    to cause a denial of service (__tcp_select_window
    divide-by-zero error and system crash) by triggering a
    disconnect within a certain tcp_recvmsg code path
    (bnc#1056982).

  - CVE-2017-14140: The move_pages system call in
    mm/migrate.c in the Linux kernel didn't check the
    effective uid of the target process, enabling a local
    attacker to learn the memory layout of a setuid
    executable despite ASLR (bnc#1057179).

  - CVE-2017-14340: The XFS_IS_REALTIME_INODE macro in
    fs/xfs/xfs_linux.h in the Linux kernel did not verify
    that a filesystem has a realtime device, which allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via vectors related to setting an
    RHINHERIT flag on a directory (bnc#1058524).

  - CVE-2017-15102: The tower_probe function in
    drivers/usb/misc/legousbtower.c in the Linux kernel
    allowed local users (who are physically proximate for
    inserting a crafted USB device) to gain privileges by
    leveraging a write-what-where condition that occurs
    after a race condition and a NULL pointer dereference
    (bnc#1066705).

  - CVE-2017-15115: The sctp_do_peeloff function in
    net/sctp/socket.c in the Linux kernel did not check
    whether the intended netns is used in a peel-off action,
    which allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via crafted system calls
    (bnc#1068671).

  - CVE-2017-15265: Race condition in the ALSA subsystem in
    the Linux kernel allowed local users to cause a denial
    of service (use-after-free) or possibly have unspecified
    other impact via crafted /dev/snd/seq ioctl calls,
    related to sound/core/seq/seq_clientmgr.c and
    sound/core/seq/seq_ports.c (bnc#1062520).

  - CVE-2017-15274: security/keys/keyctl.c in the Linux
    kernel did not consider the case of a NULL payload in
    conjunction with a nonzero length value, which allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted add_key or keyctl
    system call, a different vulnerability than
    CVE-2017-12192 (bnc#1045327).

  - CVE-2017-15868: The bnep_add_connection function in
    net/bluetooth/bnep/core.c in the Linux kernel did not
    ensure that an l2cap socket is available, which allowed
    local users to gain privileges via a crafted application
    (bnc#1071470).

  - CVE-2017-16525: The usb_serial_console_disconnect
    function in drivers/usb/serial/console.c in the Linux
    kernel allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to disconnection and failed setup (bnc#1066618).

  - CVE-2017-16527: sound/usb/mixer.c in the Linux kernel
    allowed local users to cause a denial of service
    (snd_usb_mixer_interrupt use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1066625).

  - CVE-2017-16529: The snd_usb_create_streams function in
    sound/usb/card.c in the Linux kernel allowed local users
    to cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device (bnc#1066650).

  - CVE-2017-16531: drivers/usb/core/config.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION descriptor
    (bnc#1066671).

  - CVE-2017-16534: The cdc_parse_cdc_header function in
    drivers/usb/core/message.c in the Linux kernel allowed
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1066693).

  - CVE-2017-16535: The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel allowed
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1066700).

  - CVE-2017-16536: The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel allowed local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB device
    (bnc#1066606).

  - CVE-2017-16537: The imon_probe function in
    drivers/media/rc/imon.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via a crafted USB device
    (bnc#1066573).

  - CVE-2017-16538: drivers/media/usb/dvb-usb-v2/lmedm04.c
    in the Linux kernel allowed local users to cause a
    denial of service (general protection fault and system
    crash) or possibly have unspecified other impact via a
    crafted USB device, related to a missing warm-start
    check and incorrect attach timing
    (dm04_lme2510_frontend_attach versus dm04_lme2510_tuner)
    (bnc#1066569).

  - CVE-2017-16649: The usbnet_generic_cdc_bind function in
    drivers/net/usb/cdc_ether.c in the Linux kernel allowed
    local users to cause a denial of service (divide-by-zero
    error and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1067085).

  - CVE-2017-16939: The XFRM dump policy implementation in
    net/xfrm/xfrm_user.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) via a crafted SO_RCVBUF setsockopt
    system call in conjunction with XFRM_MSG_GETPOLICY
    Netlink messages (bnc#1069702 1069708).

  - CVE-2017-17450: net/netfilter/xt_osf.c in the Linux
    kernel did not require the CAP_NET_ADMIN capability for
    add_callback and remove_callback operations, which
    allowed local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all net namespaces (bnc#1071695
    1074033).

  - CVE-2017-17558: The usb_destroy_configuration function
    in drivers/usb/core/config.c in the USB core subsystem
    in the Linux kernel did not consider the maximum number
    of configurations and interfaces before attempting to
    release resources, which allowed local users to cause a
    denial of service (out-of-bounds write access) or
    possibly have unspecified other impact via a crafted USB
    device (bnc#1072561).

  - CVE-2017-17805: The Salsa20 encryption algorithm in the
    Linux kernel did not correctly handle zero-length
    inputs, allowing a local attacker able to use the
    AF_ALG-based skcipher interface
    (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of
    service (uninitialized-memory free and kernel crash) or
    have unspecified other impact by executing a crafted
    sequence of system calls that use the blkcipher_walk
    API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 were
    vulnerable (bnc#1073792).

  - CVE-2017-17806: The HMAC implementation (crypto/hmac.c)
    in the Linux kernel did not validate that the underlying
    cryptographic hash algorithm is unkeyed, allowing a
    local attacker able to use the AF_ALG-based hash
    interface (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3
    hash algorithm (CONFIG_CRYPTO_SHA3) to cause a kernel
    stack-based buffer overflow by executing a crafted
    sequence of system calls that encounter a missing SHA-3
    initialization (bnc#1073874).

  - CVE-2017-7472: The KEYS subsystem in the Linux kernel
    allowed local users to cause a denial of service (memory
    consumption) via a series of
    KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring
    calls (bnc#1034862).

  - CVE-2017-8824: The dccp_disconnect function in
    net/dccp/proto.c in the Linux kernel allowed local users
    to gain privileges or cause a denial of service
    (use-after-free) via an AF_UNSPEC connect system call
    during the DCCP_LISTEN state (bnc#1070771).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052593"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057389"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=999245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000251/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11600/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13080/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13167/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-14340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15102/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15115/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-15868/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16525/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16527/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16531/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16534/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16535/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16536/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16537/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16939/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17558/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5754/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7472/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8824/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180040-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0ddb86e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-kernel-20170109-13398=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-20170109-13398=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-kernel-20170109-13398=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-kernel-20170109-13398=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.106.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.106.11.1")) flag++;


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
