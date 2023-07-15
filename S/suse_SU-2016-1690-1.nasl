#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1690-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93165);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9717", "CVE-2015-8816", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-2053", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-5244");
  script_bugtraq_id(74226);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:1690-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.60 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2014-9717: fs/namespace.c in the Linux kernel
    processes MNT_DETACH umount2 system called without
    verifying that the MNT_LOCKED flag is unset, which
    allowed local users to bypass intended access
    restrictions and navigate to filesystem locations
    beneath a mount by calling umount2 within a user
    namespace (bnc#928547).

  - CVE-2015-8816: The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel did not
    properly maintain a hub-interface data structure, which
    allowed physically proximate attackers to cause a denial
    of service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device (bnc#968010).

  - CVE-2015-8845: The tm_reclaim_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms did not ensure that TM suspend mode
    exists before proceeding with a tm_reclaim call, which
    allowed local users to cause a denial of service (TM Bad
    Thing exception and panic) via a crafted application
    (bnc#975533).

  - CVE-2016-0758: Fix ASN.1 indefinite length object
    parsing (bsc#979867).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-2143: The fork implementation in the Linux
    kernel on s390 platforms mishandled the case of four
    page-table levels, which allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a crafted application,
    related to arch/s390/include/asm/mmu_context.h and
    arch/s390/include/asm/pgalloc.h. (bnc#970504)

  - CVE-2016-2184: The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference or
    double free, and system crash) via a crafted endpoints
    value in a USB device descriptor (bnc#971125).

  - CVE-2016-2185: The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#971124).

  - CVE-2016-2186: The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970958).

  - CVE-2016-2188: The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#970956).

  - CVE-2016-2782: The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint (bnc#968670).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bnc#970948).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-3136: The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device without two interrupt-in
    endpoint descriptors (bnc#970955).

  - CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions (bnc#970970).

  - CVE-2016-3138: The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a USB device without both a control and a data endpoint
    descriptor (bnc#970911).

  - CVE-2016-3139: The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970909).

  - CVE-2016-3140: The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970892).

  - CVE-2016-3156: The IPv4 implementation in the Linux
    kernel mishandled destruction of device objects, which
    allowed guest OS users to cause a denial of service
    (host OS networking outage) by arranging for a large
    number of IP addresses (bnc#971360).

  - CVE-2016-3672: The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel did not properly
    randomize the legacy base address, which made it easier
    for local users to defeat the intended restrictions on
    the ADDR_NO_RANDOMIZE flag, and bypass the ASLR
    protection mechanism for a setuid or setgid program, by
    disabling stack-consumption resource limits
    (bnc#974308).

  - CVE-2016-3689: The ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) via a USB device without both a
    master and a slave interface (bnc#971628).

  - CVE-2016-3951: Double free vulnerability in
    drivers/net/usb/cdc_ncm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact by inserting a USB device with an invalid
    USB descriptor (bnc#974418).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relied on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-5244: Fixed an infoleak in rds_inc_info_copy
    (bsc#983213).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=676471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=880007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=945345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=972951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=973556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=973855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=976868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=977685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=981344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=982698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9717/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8816/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8845/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0758/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2053/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2143/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2184/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2185/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2186/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2188/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2782/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2847/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3134/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3136/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3137/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3138/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3139/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3140/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3689/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3951/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4482/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4486/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161690-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c76d1249"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-1001=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-1001=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-1001=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-1001=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-1001=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-1001=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.60-52.49.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.60-52.49.1")) flag++;


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
