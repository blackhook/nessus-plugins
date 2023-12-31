#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4374.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75554);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-3699", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3881", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4163", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4250", "CVE-2010-4251", "CVE-2010-4342", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4525", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4648", "CVE-2010-4649", "CVE-2010-4650", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0191", "CVE-2011-0521", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1493");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2011:0399-1)");
  script_summary(english:"Check for the kernel-4374 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.3 kernel was updated to 2.6.34.8 to fix various bugs
and security issues.

Following security issues have been fixed: CVE-2011-1493: In the rose
networking stack, when parsing the FAC_NATIONAL_DIGIS facilities
field, it was possible for a remote host to provide more digipeaters
than expected, resulting in heap corruption. Check against
ROSE_MAX_DIGIS to prevent overflows, and abort facilities parsing on
failure.

CVE-2011-1182: Local attackers could send signals to their programs
that looked like coming from the kernel, potentially gaining
privileges in the context of setuid programs.

CVE-2011-1082: The epoll subsystem in Linux did not prevent users from
creating circular epoll file structures, potentially leading to a
denial of service (kernel deadlock).

CVE-2011-1478: An issue in the core GRO code where an skb belonging to
an unknown VLAN is reused could result in a NULL pointer dereference.

CVE-2011-1163: The code for evaluating OSF partitions (in
fs/partitions/osf.c) contained a bug that leaks data from kernel heap
memory to userspace for certain corrupted OSF partitions.

CVE-2011-1012: The code for evaluating LDM partitions (in
fs/partitions/ldm.c) contained a bug that could crash the kernel for
certain corrupted LDM partitions.

CVE-2011-1010: The code for evaluating Mac partitions (in
fs/partitions/mac.c) contained a bug that could crash the kernel for
certain corrupted Mac partitions.

CVE-2011-1476: Specially crafted requests may be written to
/dev/sequencer resulting in an underflow when calculating a size for a
copy_from_user() operation in the driver for MIDI interfaces. On x86,
this just returns an error, but it could have caused memory corruption
on other architectures. Other malformed requests could have resulted
in the use of uninitialized variables.

CVE-2011-1477: Due to a failure to validate user-supplied indexes in
the driver for Yamaha YM3812 and OPL-3 chips, a specially crafted
ioctl request could have been sent to /dev/sequencer, resulting in
reading and writing beyond the bounds of heap buffers, and potentially
allowing privilege escalation.

CVE-2011-0191: A information leak in the XFS geometry calls could be
used by local attackers to gain access to kernel information.

CVE-2011-1090: A page allocator issue in NFS v4 ACL handling that
could lead to a denial of service (crash) was fixed.

CVE-2010-3880: net/ipv4/inet_diag.c in the Linux kernel did not
properly audit INET_DIAG bytecode, which allowed local users to cause
a denial of service (kernel infinite loop) via crafted
INET_DIAG_REQ_BYTECODE instructions in a netlink message that contains
multiple attribute elements, as demonstrated by INET_DIAG_BC_JMP
instructions.

CVE-2010-4656: Fixed a buffer size issue in 'usb iowarrior' module,
where a malicious device could overflow a kernel buffer.

CVE-2011-0521: The dvb_ca_ioctl function in
drivers/media/dvb/ttpci/av7110_ca.c in the Linux kernel did not check
the sign of a certain integer field, which allowed local users to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via a negative value.

CVE-2010-3875: The ax25_getname function in net/ax25/af_ax25.c in the
Linux kernel did not initialize a certain structure, which allowed
local users to obtain potentially sensitive information from kernel
stack memory by reading a copy of this structure.

CVE-2010-3876: net/packet/af_packet.c in the Linux kernel did not
properly initialize certain structure members, which allowed local
users to obtain potentially sensitive information from kernel stack
memory by leveraging the CAP_NET_RAW capability to read copies of the
applicable structures.

CVE-2010-3877: The get_name function in net/tipc/socket.c in the Linux
kernel did not initialize a certain structure, which allowed local
users to obtain potentially sensitive information from kernel stack
memory by reading a copy of this structure.

CVE-2010-3705: The sctp_auth_asoc_get_hmac function in net/sctp/auth.c
in the Linux kernel did not properly validate the hmac_ids array of an
SCTP peer, which allowed remote attackers to cause a denial of service
(memory corruption and panic) via a crafted value in the last element
of this array.

CVE-2011-0711: A stack memory information leak in the xfs
FSGEOMETRY_V1 ioctl was fixed.

CVE-2011-0712: Multiple buffer overflows in the caiaq Native
Instruments USB audio functionality in the Linux kernel might have
allowed attackers to cause a denial of service or possibly have
unspecified other impact via a long USB device name, related to (1)
the snd_usb_caiaq_audio_init function in sound/usb/caiaq/audio.c and
(2) the snd_usb_caiaq_midi_init function in sound/usb/caiaq/midi.c.

CVE-2010-4525: Linux kernel did not initialize the
kvm_vcpu_events->interrupt.pad structure member, which allowed local
users to obtain potentially sensitive information from kernel stack
memory via unspecified vectors.

CVE-2010-3881: arch/x86/kvm/x86.c in the Linux kernel did not
initialize certain structure members, which allowed local users to
obtain potentially sensitive information from kernel stack memory via
read operations on the /dev/kvm device.

CVE-2010-4075: The uart_get_count function in
drivers/serial/serial_core.c in the Linux kernel did not properly
initialize a certain structure member, which allowed local users to
obtain potentially sensitive information from kernel stack memory via
a TIOCGICOUNT ioctl call.

CVE-2010-4076: The rs_ioctl function in drivers/char/amiserial.c in
the Linux kernel did not properly initialize a certain structure
member, which allowed local users to obtain potentially sensitive
information from kernel stack memory via a TIOCGICOUNT ioctl call.

CVE-2010-4077: The ntty_ioctl_tiocgicount function in
drivers/char/nozomi.c in the Linux kernel did not properly initialize
a certain structure member, which allowed local users to obtain
potentially sensitive information from kernel stack memory via a
TIOCGICOUNT ioctl call.

CVE-2010-4248: Race condition in the __exit_signal function in
kernel/exit.c in the Linux kernel allowed local users to cause a
denial of service via vectors related to multithreaded exec, the use
of a thread group leader in kernel/posix-cpu-timers.c, and the
selection of a new thread group leader in the de_thread function in
fs/exec.c.

CVE-2010-4243: fs/exec.c in the Linux kernel did not enable the OOM
Killer to assess use of stack memory by arrays representing the (1)
arguments and (2) environment, which allows local users to cause a
denial of service (memory consumption) via a crafted exec system call,
aka an 'OOM dodging issue,' a related issue to CVE-2010-3858.

CVE-2010-4251: A system out of memory condition (denial of service)
could be triggered with a large socket backlog, exploitable by local
users. This has been addressed by backlog limiting.

CVE-2010-4648: Fixed cryptographic weakness potentially leaking
information to remote (but physically nearby) users in the orinoco
wireless driver.

CVE-2010-4527: The load_mixer_volumes function in
sound/oss/soundcard.c in the OSS sound subsystem in the Linux kernel
incorrectly expected that a certain name field ends with a '\0'
character, which allowed local users to conduct buffer overflow
attacks and gain privileges, or possibly obtain sensitive information
from kernel memory, via a SOUND_MIXER_SETLEVELS ioctl call.

CVE-2010-4668: The blk_rq_map_user_iov function in block/blk-map.c in
the Linux kernel allowed local users to cause a denial of service
(panic) via a zero-length I/O request in a device ioctl to a SCSI
device, related to an unaligned map. NOTE: this vulnerability exists
because of an incomplete fix for CVE-2010-4163.

CVE-2010-4650: A kernel buffer overflow in the cuse server module was
fixed, which might have allowed local privilege escalation. However
only CUSE servers could exploit it and /dev/cuse is normally
restricted to root.

CVE-2010-4649: Integer overflow in the ib_uverbs_poll_cq function in
drivers/infiniband/core/uverbs_cmd.c in the Linux kernel allowed local
users to cause a denial of service (memory corruption) or possibly
have unspecified other impact via a large value of a certain structure
member.

CVE-2010-4250: A memory leak within inotify could be used by local
attackers to cause the machine to run out of memory (denial of
service).

CVE-2010-4346: The install_special_mapping function in mm/mmap.c in
the Linux kernel did not make an expected security_file_mmap function
call, which allowed local users to bypass intended mmap_min_addr
restrictions and possibly conduct NULL pointer dereference attacks via
a crafted assembly-language application.

CVE-2010-4529: Integer underflow in the irda_getsockopt function in
net/irda/af_irda.c in the Linux kernel on platforms other than x86
allowed local users to obtain potentially sensitive information from
kernel heap memory via an IRLMP_ENUMDEVICES getsockopt call.

CVE-2010-4342: The aun_incoming function in net/econet/af_econet.c in
the Linux kernel, when Econet is enabled, allowed remote attackers to
cause a denial of service (NULL pointer dereference and OOPS) by
sending an Acorn Universal Networking (AUN) packet over UDP.

CVE-2010-3849: The econet_sendmsg function in net/econet/af_econet.c
in the Linux kernel, when an econet address is configured, allowed
local users to cause a denial of service (NULL pointer dereference and
OOPS) via a sendmsg call that specifies a NULL value for the remote
address field.

CVE-2010-3848: Stack-based buffer overflow in the econet_sendmsg
function in net/econet/af_econet.c in the Linux kernel when an econet
address is configured, allowed local users to gain privileges by
providing a large number of iovec structures.

CVE-2010-3850: The ec_dev_ioctl function in net/econet/af_econet.c in
the Linux kernel did not require the CAP_NET_ADMIN capability, which
allowed local users to bypass intended access restrictions and
configure econet addresses via an SIOCSIFADDR ioctl call.

CVE-2010-4343: drivers/scsi/bfa/bfa_core.c in the Linux kernel did not
initialize a certain port data structure, which allows local users to
cause a denial of service (system crash) via read operations on an
fc_host statistics file.

CVE-2010-3699: The backend driver in Xen 3.x allows guest OS users to
cause a denial of service via a kernel thread leak, which prevents the
device and guest OS from being shut down or create a zombie domain,
causes a hang in zenwatch, or prevents unspecified xm commands from
working properly, related to (1) netback, (2) blkback, or (3) blktap."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=625965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=641105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=644807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=647632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=671256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-04/msg00074.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-extra-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.8-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.8_0.2-19.1.19") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.8_0.2-19.1.19") ) flag++;

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
