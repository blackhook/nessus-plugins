#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0438-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146474);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2019-20806",
    "CVE-2019-20934",
    "CVE-2020-0444",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-4788",
    "CVE-2020-10781",
    "CVE-2020-11668",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25211",
    "CVE-2020-25639",
    "CVE-2020-25669",
    "CVE-2020-27068",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-27825",
    "CVE-2020-27835",
    "CVE-2020-28374",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29371",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158",
    "CVE-2021-3347",
    "CVE-2021-3348"
  );

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:0438-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2021-3348: Fixed a use-after-free in nbd_add_socket that could be
triggered by local attackers (with access to the nbd device) via an
I/O request at a certain point during device setup (bnc#1181504).

CVE-2021-3347: A use-after-free was discovered in the PI futexes
during fault handling, allowing local users to execute code in the
kernel (bnc#1181349).

CVE-2020-25211: Fixed a buffer overflow in
ctnetlink_parse_tuple_filter() which could be triggered by a local
attackers by injecting conntrack netlink configuration (bnc#1176395).

CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was
found, specifically in the way user calls Ioctl after open dev file
and fork. A local user could use this flaw to crash the system
(bnc#1179878).

CVE-2020-29569: Fixed a potential privilege escalation and information
leaks related to the PV block backend, as used by Xen (bnc#1179509).

CVE-2020-29568: Fixed a denial of service issue, related to processing
watch events (bnc#1179508).

CVE-2020-0444: Fixed a bad kfree due to a logic error in
audit_data_to_entry (bnc#1180027).

CVE-2020-0465: Fixed multiple missing bounds checks in
hid-multitouch.c that could have led to local privilege escalation
(bnc#1180029).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).

CVE-2020-4788: Fixed an issue with IBM Power9 processors could have
allowed a local user to obtain sensitive information from the data in
the L1 cache under extenuating circumstances (bsc#1177666).

CVE-2020-10781: A flaw was found in the ZRAM kernel module, where a
user with a local account and the ability to read the
/sys/class/zram-control/hot_add file can create ZRAM device nodes in
the /dev/ directory. This read allocates kernel memory and is not
accounted for a user that triggers the creation of that ZRAM device.
With this vulnerability, continually reading the device may consume a
large amount of system memory and cause the Out-of-Memory (OOM) killer
to activate and terminate random userspace processes, possibly making
the system inoperable (bnc#1173074).

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
which could have allowed local users to gain privileges or cause a
denial of service (bsc#1179141).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-25639: Fixed a NULL pointer dereference via nouveau ioctl
(bnc#1176846).

CVE-2020-27777: Fixed a privilege escalation in the Run-Time
Abstraction Services (RTAS) interface, affecting guests running on top
of PowerVM or KVM hypervisors (bnc#1179107).

CVE-2020-27786: Fixed an out-of-bounds write in the MIDI
implementation (bnc#1179601).

CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls
(bsc#1179960).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem
that may have allowed a read-after-free attack against TIOCGSID
(bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that
allowed a use-after-free attack against TIOCSPGRP (bsc#1179745).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
have been used by local attackers to read privileged information or
potentially crash the kernel (bsc#1178589).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-28374: Fixed a Linux SCSI target issue (bsc#1178372).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
(bsc#1178182).

CVE-2020-29371: An issue was discovered in romfs_dev_read in
fs/romfs/storage.c where uninitialized memory leaks to userspace
(bnc#1179429).

CVE-2020-15437: Fixed a NULL pointer dereference which could have
allowed local users to cause a denial of service(bsc#1179140).

CVE-2020-36158: Fixed a potential remote code execution in the Marvell
mwifiex driver (bsc#1180559).

CVE-2020-11668: Fixed the mishandling of invalid descriptors in the
Xirlink camera USB driver (bnc#1168952).

CVE-2019-20934: Fixed a use-after-free in show_numa_stats() because
NUMA fault statistics were inappropriately freed (bsc#1179663).

CVE-2019-20806: Fixed a NULL pointer dereference in
tw5864_handle_frame() in drivers/media/pci/tw5864/tw5864-video.c,
which may cause denial of service (bnc#1172199).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1144912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1163840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1173942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20806/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20934/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0444/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0465/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0466/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10781/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11668/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15436/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15437/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25211/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25639/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25669/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27068/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27777/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27786/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27825/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27835/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28374/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28915/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28974/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29371/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29568/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29569/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29660/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29661/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36158/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-4788/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3347/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3348/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210438-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f57dfef");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-438=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-438=1

SUSE Linux Enterprise Module for Live Patching 15 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-2021-438=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-438=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-438=1

SUSE Linux Enterprise High Availability 15 :

zypper in -t patch SUSE-SLE-Product-HA-15-2021-438=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-base-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debuginfo-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debugsource-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-debuginfo-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-debugsource-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-syms-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-debuginfo-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debuginfo-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debugsource-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-4.12.14-150.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-debuginfo-4.12.14-150.66.1")) flag++;


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
