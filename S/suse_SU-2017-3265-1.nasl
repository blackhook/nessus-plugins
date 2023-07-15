#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3265-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105172);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000112", "CVE-2017-10661", "CVE-2017-12192", "CVE-2017-12762", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16649", "CVE-2017-8831");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:3265-1) (KRACK)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes. The following security bugs were fixed :

  - CVE-2017-16649: The usbnet_generic_cdc_bind function in
    drivers/net/usb/cdc_ether.c in the Linux kernel allowed
    local users to cause a denial of service (divide-by-zero
    error and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1067085).

  - CVE-2017-16535: The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel allowed
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1066700).

  - CVE-2017-15102: The tower_probe function in
    drivers/usb/misc/legousbtower.c in the Linux kernel
    allowed local users (who are physically proximate for
    inserting a crafted USB device) to gain privileges by
    leveraging a write-what-where condition that occurs
    after a race condition and a NULL pointer dereference
    (bnc#1066705).

  - CVE-2017-16531: drivers/usb/core/config.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION descriptor
    (bnc#1066671).

  - CVE-2017-16529: The snd_usb_create_streams function in
    sound/usb/card.c in the Linux kernel allowed local users
    to cause a denial of service (out-of-bounds read and
    system crash) or possibly have unspecified other impact
    via a crafted USB device (bnc#1066650).

  - CVE-2017-16525: The usb_serial_console_disconnect
    function in drivers/usb/serial/console.c in the Linux
    kernel allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to disconnection and failed setup (bnc#1066618).

  - CVE-2017-16537: The imon_probe function in
    drivers/media/rc/imon.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via a crafted USB device
    (bnc#1066573).

  - CVE-2017-16536: The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel allowed local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact via a crafted USB device
    (bnc#1066606).

  - CVE-2017-16527: sound/usb/mixer.c in the Linux kernel
    allowed local users to cause a denial of service
    (snd_usb_mixer_interrupt use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device (bnc#1066625).

  - CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2)
    allowed reinstallation of the Group Temporal Key (GTK)
    during the group key handshake, allowing an attacker
    within radio range to replay frames from access points
    to clients (bnc#1063667).

  - CVE-2017-15274: security/keys/keyctl.c in the Linux
    kernel did not consider the case of a NULL payload in
    conjunction with a nonzero length value, which allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a crafted add_key or keyctl
    system call, a different vulnerability than
    CVE-2017-12192 (bnc#1045327).

  - CVE-2017-15265: Race condition in the ALSA subsystem in
    the Linux kernel allowed local users to cause a denial
    of service (use-after-free) or possibly have unspecified
    other impact via crafted /dev/snd/seq ioctl calls,
    related to sound/core/seq/seq_clientmgr.c and
    sound/core/seq/seq_ports.c (bnc#1062520).

  - CVE-2017-14489: The iscsi_if_rx function in
    drivers/scsi/scsi_transport_iscsi.c in the Linux kernel
    allowed local users to cause a denial of service (panic)
    by leveraging incorrect length validation (bnc#1059051).

  - CVE-2017-14340: The XFS_IS_REALTIME_INODE macro in
    fs/xfs/xfs_linux.h in the Linux kernel did not verify
    that a filesystem has a realtime device, which allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via vectors related to setting an
    RHINHERIT flag on a directory (bnc#1058524).

  - CVE-2017-14140: The move_pages system call in
    mm/migrate.c in the Linux kernel doesn't check the
    effective uid of the target process, enabling a local
    attacker to learn the memory layout of a setuid
    executable despite ASLR (bnc#1057179).

  - CVE-2017-14051: An integer overflow in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash) by leveraging root access
    (bnc#1056588).

  - CVE-2017-10661: Race condition in fs/timerfd.c in the
    Linux kernel allowed local users to gain privileges or
    cause a denial of service (list corruption or
    use-after-free) via simultaneous file-descriptor
    operations that leverage improper might_cancel queueing
    (bnc#1053152).

  - CVE-2017-12762: In /drivers/isdn/i4l/isdn_net.c: A
    user-controlled buffer is copied into a local buffer of
    constant size using strcpy without a length check which
    can cause a buffer overflow. (bnc#1053148).

  - CVE-2017-8831: The saa7164_bus_get function in
    drivers/media/pci/saa7164/saa7164-bus.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds array access) or possibly have
    unspecified other impact by changing a certain
    sequence-number value, aka a 'double fetch'
    vulnerability (bnc#1037994).

  - CVE-2017-1000112: An exploitable memory corruption due
    to UFO to non-UFO path switch was fixed. (bnc#1052311
    bnc#1052365).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1024450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052370"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063301"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066472"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=996376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10661/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-14140/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14489/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15102/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-16649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8831/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173265-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1e5f1fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-20171124-13375=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-20171124-13375=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-20171124-13375=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-20171124-13375=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-108.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-108.18.1")) flag++;


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
