#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0168.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104454);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10044", "CVE-2017-1000363", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11473", "CVE-2017-14489", "CVE-2017-2671", "CVE-2017-8831", "CVE-2017-9075", "CVE-2017-9077");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2017-0168)");
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
    entry points (Eric Ren) [Orabug: 26427126] -
    ocfs2/dlmglue: prepare tracking logic to avoid recursive
    cluster lock (Eric Ren) [Orabug: 26427126] - ping:
    implement proper locking (Eric Dumazet) [Orabug:
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
    AOP_TRUNCATED_PAGE (Abhi Das) [Orabug: 26797306] -
    timerfd: Protect the might cancel mechanism proper
    (Thomas Gleixner) [Orabug: 26899787] (CVE-2017-10661)

  - scsi: scsi_transport_iscsi: fix the issue that
    iscsi_if_rx doesn't parse nlmsg properly (Xin Long)
    [Orabug: 26988627] (CVE-2017-14489)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-November/000799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82da82bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");
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
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.19.12.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.19.12.el6uek")) flag++;

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
