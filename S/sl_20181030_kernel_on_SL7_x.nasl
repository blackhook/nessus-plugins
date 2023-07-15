#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119187);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2015-8830", "CVE-2016-4913", "CVE-2017-0861", "CVE-2017-10661", "CVE-2017-17805", "CVE-2017-18208", "CVE-2017-18232", "CVE-2017-18344", "CVE-2018-1000026", "CVE-2018-10322", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10881", "CVE-2018-10883", "CVE-2018-10902", "CVE-2018-1092", "CVE-2018-1094", "CVE-2018-10940", "CVE-2018-1118", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-13405", "CVE-2018-5344", "CVE-2018-5391", "CVE-2018-5803", "CVE-2018-5848", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-8781");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20181030)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - A flaw named FragmentSmack was found in the way the
    Linux kernel handled reassembly of fragmented IPv4 and
    IPv6 packets. A remote attacker could use this flaw to
    trigger time and calculation expensive fragment
    reassembly algorithm by sending specially crafted
    packets which could lead to a CPU saturation and hence a
    denial of service on the system. (CVE-2018-5391)

  - kernel: out-of-bounds access in the show_timer function
    in kernel/time /posix-timers.c (CVE-2017-18344)

  - kernel: Integer overflow in udl_fb_mmap() can allow
    attackers to execute code in kernel space
    (CVE-2018-8781)

  - kernel: MIDI driver race condition leads to a
    double-free (CVE-2018-10902)

  - kernel: Missing check in inode_init_owner() does not
    clear SGID bit on non-directories for non-members
    (CVE-2018-13405)

  - kernel: AIO write triggers integer overflow in some
    protocols (CVE-2015-8830)

  - kernel: Use-after-free in snd_pcm_info function in ALSA
    subsystem potentially leads to privilege escalation
    (CVE-2017-0861)

  - kernel: Handling of might_cancel queueing is not
    properly pretected against race (CVE-2017-10661)

  - kernel: Salsa20 encryption algorithm does not correctly
    handle zero- length inputs allowing local attackers to
    cause denial of service (CVE-2017-17805)

  - kernel: Inifinite loop vulnerability in
    madvise_willneed() function allows local denial of
    service (CVE-2017-18208)

  - kernel: fuse-backed file mmap-ed onto process cmdline
    arguments causes denial of service (CVE-2018-1120)

  - kernel: a NULL pointer dereference in dccp_write_xmit()
    leads to a system crash (CVE-2018-1130)

  - kernel: drivers/block/loop.c mishandles lo_release
    serialization allowing denial of service (CVE-2018-5344)

  - kernel: Missing length check of payload in
    _sctp_make_chunk() function allows denial of service
    (CVE-2018-5803)

  - kernel: buffer overflow in
    drivers/net/wireless/ath/wil6210/wmi.c:wmi_set_ie() may
    lead to memory corruption (CVE-2018-5848)

  - kernel: out-of-bound write in ext4_init_block_bitmap
    function with a crafted ext4 image (CVE-2018-10878)

  - kernel: Improper validation in bnx2x network card driver
    can allow for denial of service attacks via crafted
    packet (CVE-2018-1000026)

  - kernel: Information leak when handling NM entries
    containing NUL (CVE-2016-4913)

  - kernel: Mishandling mutex within libsas allowing local
    Denial of Service (CVE-2017-18232)

  - kernel: NULL pointer dereference in
    ext4_process_freed_data() when mounting crafted ext4
    image (CVE-2018-1092)

  - kernel: NULL pointer dereference in
    ext4_xattr_inode_hash() causes crash with crafted ext4
    image (CVE-2018-1094)

  - kernel: vhost: Information disclosure in
    vhost/vhost.c:vhost_new_msg() (CVE-2018-1118)

  - kernel: Denial of service in resv_map_release function
    in mm/hugetlb.c (CVE-2018-7740)

  - kernel: Memory leak in the sas_smp_get_phy_events
    function in drivers/scsi/libsas/sas_expander.c
    (CVE-2018-7757)

  - kernel: Invalid pointer dereference in
    xfs_ilock_attr_map_shared() when mounting crafted xfs
    image allowing denial of service (CVE-2018-10322)

  - kernel: use-after-free detected in ext4_xattr_set_entry
    with a crafted file (CVE-2018-10879)

  - kernel: out-of-bound access in ext4_get_group_info()
    when mounting and operating a crafted ext4 image
    (CVE-2018-10881)

  - kernel: stack-out-of-bounds write in
    jbd2_journal_dirty_metadata function (CVE-2018-10883)

  - kernel: incorrect memory bounds check in
    drivers/cdrom/cdrom.c (CVE-2018-10940)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1811&L=scientific-linux-errata&F=&S=&P=8524
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faf0e575"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10661");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"bpftool-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-957.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-957.el7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc");
}
