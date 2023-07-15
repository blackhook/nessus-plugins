#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0173.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105147);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10044", "CVE-2016-10200", "CVE-2016-7097", "CVE-2016-9604", "CVE-2016-9685", "CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11176", "CVE-2017-11473", "CVE-2017-12134", "CVE-2017-12190", "CVE-2017-14489", "CVE-2017-2671", "CVE-2017-7542", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-8831", "CVE-2017-9075", "CVE-2017-9077", "CVE-2017-9242");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2017-0173) (BlueBorne) (Stack Clash)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - tty: Fix race in pty_write leading to NULL deref (Todd
    Vierling) 

  - ocfs2/dlm: ignore cleaning the migration mle that is
    inuse (xuejiufei) [Orabug: 26479780]

  - KEYS: fix dereferencing NULL payload with nonzero length
    (Eric Biggers) [Orabug: 26592025]

  - oracleasm: Copy the integrity descriptor (Martin K.
    Petersen) 

  - mm: Tighten x86 /dev/mem with zeroing reads (Kees Cook)
    [Orabug: 26675925] (CVE-2017-7889)

  - xscore: add dma address check (Zhu Yanjun) [Orabug:
    27058468]

  - more bio_map_user_iov leak fixes (Al Viro) [Orabug:
    27069042] (CVE-2017-12190)

  - fix unbalanced page refcounting in bio_map_user_iov
    (Vitaly Mayatskikh) [Orabug: 27069042] (CVE-2017-12190)

  - nvme: Drop nvmeq->q_lock before dma_pool_alloc, so as to
    prevent hard lockups (Aruna Ramakrishna) [Orabug:
    25409587]

  - nvme: Handle PM1725 HIL reset (Martin K. Petersen)
    [Orabug: 26277600]

  - char: lp: fix possible integer overflow in lp_setup
    (Willy Tarreau) [Orabug: 26403940] (CVE-2017-1000363)

  - ALSA: timer: Fix missing queue indices reset at
    SNDRV_TIMER_IOCTL_SELECT (Takashi Iwai) [Orabug:
    26403956] (CVE-2017-1000380)

  - ALSA: timer: Fix race between read and ioctl (Takashi
    Iwai) [Orabug: 26403956] (CVE-2017-1000380)

  - ALSA: timer: fix NULL pointer dereference in read/ioctl
    race (Vegard Nossum) [Orabug: 26403956]
    (CVE-2017-1000380)

  - ALSA: timer: Fix negative queue usage by racy accesses
    (Takashi Iwai) [Orabug: 26403956] (CVE-2017-1000380)

  - ALSA: timer: Fix race at concurrent reads (Takashi Iwai)
    [Orabug: 26403956] (CVE-2017-1000380)

  - ALSA: timer: Fix race among timer ioctls (Takashi Iwai)
    [Orabug: 26403956] (CVE-2017-1000380)

  - ipv6/dccp: do not inherit ipv6_mc_list from parent (WANG
    Cong) [Orabug: 26404005] (CVE-2017-9077)

  - ocfs2: fix deadlock issue when taking inode lock at vfs
    entry points (Eric Ren) [Orabug: 26427126]

  - ocfs2/dlmglue: prepare tracking logic to avoid recursive
    cluster lock (Eric Ren) [Orabug: 26427126]

  - ping: implement proper locking (Eric Dumazet) [Orabug:
    26540286] (CVE-2017-2671)

  - aio: mark AIO pseudo-fs noexec (Jann Horn) [Orabug:
    26643598] (CVE-2016-10044)

  - vfs: Commit to never having exectuables on proc and
    sysfs. (Eric W. Biederman) [Orabug: 26643598]
    (CVE-2016-10044)

  - vfs, writeback: replace FS_CGROUP_WRITEBACK with
    SB_I_CGROUPWB (Tejun Heo) [Orabug: 26643598]
    (CVE-2016-10044)

  - x86/acpi: Prevent out of bound access caused by broken
    ACPI tables (Seunghun Han) [Orabug: 26643645]
    (CVE-2017-11473)

  - sctp: do not inherit ipv6_[mc|ac|fl]_list from parent
    (Eric Dumazet) [Orabug: 26650883] (CVE-2017-9075)

  - [media] saa7164: fix double fetch PCIe access condition
    (Steven Toth) [Orabug: 26675142] (CVE-2017-8831)

  - [media] saa7164: fix sparse warnings (Hans Verkuil)
    [Orabug: 26675142] (CVE-2017-8831)

  - fs: __generic_file_splice_read retry lookup on
    AOP_TRUNCATED_PAGE (Abhi Das) [Orabug: 26797306]

  - timerfd: Protect the might cancel mechanism proper
    (Thomas Gleixner) [Orabug: 26899787] (CVE-2017-10661)

  - scsi: scsi_transport_iscsi: fix the issue that
    iscsi_if_rx doesn't parse nlmsg properly (Xin Long)
    [Orabug: 26988627] (CVE-2017-14489)

  - mqueue: fix a use-after-free in sys_mq_notify (Cong
    Wang) [Orabug: 26643556] (CVE-2017-11176)

  - ipv6: avoid overflow of offset in ip6_find_1stfragopt
    (Sabrina Dubroca) [Orabug: 27011273] (CVE-2017-7542)

  - packet: fix tp_reserve race in packet_set_ring (Willem
    de Bruijn) [Orabug: 27002450] (CVE-2017-1000111)

  - mlx4_core: calculate log_num_mtt based on total system
    memory (Wei Lin Guay) [Orabug: 26883934]

  - xen/x86: Add interface for querying amount of host
    memory (Boris Ostrovsky) [Orabug: 26883934]

  - Bluetooth: Properly check L2CAP config option output
    buffer length (Ben Seri) [Orabug: 26796364]
    (CVE-2017-1000251)

  - xen: fix bio vec merging (Roger Pau Monne) [Orabug:
    26645550] (CVE-2017-12134)

  - fs/exec.c: account for argv/envp pointers (Kees Cook)
    [Orabug: 26638921] (CVE-2017-1000365) (CVE-2017-1000365)

  - l2tp: fix racy SOCK_ZAPPED flag check in
    l2tp_ip[,6]_bind (Guillaume Nault) [Orabug: 26586047]
    (CVE-2016-10200)

  - xfs: fix two memory leaks in xfs_attr_list.c error paths
    (Mateusz Guzik) [Orabug: 26586022] (CVE-2016-9685)

  - KEYS: Disallow keyrings beginning with '.' to be joined
    as session keyrings (David Howells) [Orabug: 26585994]
    (CVE-2016-9604)

  - ipv6: fix out of bound writes in __ip6_append_data (Eric
    Dumazet) [Orabug: 26578198] (CVE-2017-9242)

  - posix_acl: Clear SGID bit when setting file permissions
    (Jan Kara) [Orabug: 25507344] (CVE-2016-7097)
    (CVE-2016-7097)

  - nfsd: check for oversized NFSv2/v3 arguments (J. Bruce
    Fields) [Orabug: 26366022] (CVE-2017-7645)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-December/000804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08785912"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.20.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.20.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
