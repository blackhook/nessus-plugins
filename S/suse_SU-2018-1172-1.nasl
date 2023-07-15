#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1172-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109646);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-5156", "CVE-2016-7915", "CVE-2017-0861", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-16644", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18203", "CVE-2017-18208", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1087", "CVE-2018-6927", "CVE-2018-7566", "CVE-2018-7757", "CVE-2018-8822", "CVE-2018-8897");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2018:1172-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2018-1087: And an unprivileged KVM guest user could
    use this flaw to potentially escalate their privileges
    inside a guest. (bsc#1087088)

  - CVE-2018-8897: An unprivileged system user could use
    incorrect set up interrupt stacks to crash the Linux
    kernel resulting in DoS issue. (bsc#1087088)

  - CVE-2018-10124: The kill_something_info function in
    kernel/signal.c might allow local users to cause a
    denial of service via an INT_MIN argument (bnc#1089752).

  - CVE-2018-10087: The kernel_wait4 function in
    kernel/exit.c might allow local users to cause a denial
    of service by triggering an attempted use of the
    -INT_MIN value (bnc#1089608).

  - CVE-2018-7757: Memory leak in the sas_smp_get_phy_events
    function in drivers/scsi/libsas/sas_expander.c allowed
    local users to cause a denial of service (memory
    consumption) via many read accesses to files in the
    /sys/class/sas_phy directory, as demonstrated by the
    /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file
    (bnc#1084536 1087209).

  - CVE-2018-7566: A Buffer Overflow via an
    SNDRV_SEQ_IOCTL_SET_CLIENT_POOL ioctl write operation to
    /dev/snd/seq by a local user was fixed (bnc#1083483).

  - CVE-2017-0861: Use-after-free vulnerability in the
    snd_pcm_info function in the ALSA subsystem allowed
    attackers to gain privileges via unspecified vectors
    (bnc#1088260).

  - CVE-2018-8822: Incorrect buffer length handling in the
    ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c
    could be exploited by malicious NCPFS servers to crash
    the kernel or execute code (bnc#1086162).

  - CVE-2017-13166: An elevation of privilege vulnerability
    in the kernel v4l2 video driver. (bnc#1072865).

  - CVE-2017-18203: The dm_get_from_kobject function in
    drivers/md/dm.c allow local users to cause a denial of
    service (BUG) by leveraging a race condition with
    __dm_destroy during creation and removal of DM devices
    (bnc#1083242).

  - CVE-2017-16911: The vhci_hcd driver allowed allows local
    attackers to disclose kernel memory addresses.
    Successful exploitation requires that a USB device is
    attached over IP (bnc#1078674).

  - CVE-2017-18208: The madvise_willneed function in
    mm/madvise.c allowed local users to cause a denial of
    service (infinite loop) by triggering use of
    MADVISE_WILLNEED for a DAX mapping (bnc#1083494).

  - CVE-2017-16644: The hdpvr_probe function in
    drivers/media/usb/hdpvr/hdpvr-core.c allowed local users
    to cause a denial of service (improper error handling
    and system crash) or possibly have unspecified other
    impact via a crafted USB device (bnc#1067118).

  - CVE-2018-6927: The futex_requeue function in
    kernel/futex.c might allow attackers to cause a denial
    of service (integer overflow) or possibly have
    unspecified other impact by triggering a negative wake
    or requeue value (bnc#1080757).

  - CVE-2017-16914: The 'stub_send_ret_submit()' function
    (drivers/usb/usbip/stub_tx.c) allowed attackers to cause
    a denial of service (NULL pointer dereference) via a
    specially crafted USB over IP packet (bnc#1078669).

  - CVE-2016-7915: The hid_input_field function in
    drivers/hid/hid-core.c allowed physically proximate
    attackers to obtain sensitive information from kernel
    memory or cause a denial of service (out-of-bounds read)
    by connecting a device, as demonstrated by a Logitech DJ
    receiver (bnc#1010470).

  - CVE-2015-5156: The virtnet_probe function in
    drivers/net/virtio_net.c attempted to support a FRAGLIST
    feature without proper memory allocation, which allowed
    guest OS users to cause a denial of service (buffer
    overflow and memory corruption) via a crafted sequence
    of fragmented packets (bnc#940776).

  - CVE-2017-12190: The bio_map_user_iov and bio_unmap_user
    functions in block/bio.c did unbalanced refcounting when
    a SCSI I/O vector has small consecutive buffers
    belonging to the same page. The bio_add_pc_page function
    merges them into one, but the page reference is never
    dropped. This causes a memory leak and possible system
    lockup (exploitable against the host OS by a guest OS
    user, if a SCSI disk is passed through to a virtual
    machine) due to an out-of-memory condition
    (bnc#1062568).

  - CVE-2017-16912: The 'get_pipe()' function
    (drivers/usb/usbip/stub_rx.c) allowed attackers to cause
    a denial of service (out-of-bounds read) via a specially
    crafted USB over IP packet (bnc#1078673).

  - CVE-2017-16913: The 'stub_recv_cmd_submit()' function
    (drivers/usb/usbip/stub_rx.c) when handling CMD_SUBMIT
    packets allowed attackers to cause a denial of service
    (arbitrary memory allocation) via a specially crafted
    USB over IP packet (bnc#1078672).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1010470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1085331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7915/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-0861/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12190/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13166/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16912/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16913/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16914/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18203/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18208/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10087/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10124/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1087/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6927/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7566/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8822/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8897/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181172-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1abfbd41"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-kernel-source-20180429-13591=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-source-20180429-13591=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-kernel-source-20180429-13591=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-kernel-source-20180429-13591=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.106.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.106.22.1")) flag++;


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
