#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0009.
#

include("compat.inc");

if (description)
{
  script_id(122837);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id("CVE-2017-17807", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-16862", "CVE-2018-18559", "CVE-2018-9568");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0009)");
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

  - NFS: commit direct writes even if they fail partially
    (J. Bruce Fields) [Orabug: 28212440]

  - rds: update correct congestion map for loopback
    transport (Mukesh Kacker) [Orabug: 29175685]

  - ext4: only look at the bg_flags field if it is valid
    (Theodore Ts'o) [Orabug: 29316684] (CVE-2018-10876)
    (CVE-2018-10876)

  - uek-rpm: Add kernel-uek version to kernel-ueknano
    provides (Somasundaram Krishnasamy) [Orabug: 29357643]

  - net: Set sk_prot_creator when cloning sockets to the
    right proto (Christoph Paasch) [Orabug: 29422739]
    (CVE-2018-9568)

  - ext4: always check block group bounds in
    ext4_init_block_bitmap (Theodore Ts'o) [Orabug:
    29428607] (CVE-2018-10878)

  - ext4: make sure bitmaps and the inode table don't
    overlap with bg descriptors (Theodore Ts'o) [Orabug:
    29428607] (CVE-2018-10878)

  - vfs: Add sb_rdonly(sb) to query the MS_RDONLY flag on
    s_flags (David Howells) [Orabug: 29428607]
    (CVE-2018-10878)

  - iscsi: Capture iscsi debug messages using tracepoints
    (Fred Herard) [Orabug: 29429855]

  - KEYS: add missing permission check for request_key
    destination (Eric Biggers) [Orabug: 29304551]
    (CVE-2017-17807)

  - KEYS: Don't permit request_key to construct a new
    keyring (David Howells) [Orabug: 29304551]
    (CVE-2017-17807)

  - mlx4_ib: Distribute completion vectors when zero is
    supplied (H&aring kon Bugge) [Orabug: 29318191]

  - bnxt_en: Fix TX timeout during netpoll. (Michael Chan)
    [Orabug: 29357977]

  - bnxt_en: Fix for system hang if request_irq fails (Vikas
    Gupta) [Orabug: 29357977]

  - bnxt_en: Fix firmware message delay loop regression.
    (Michael Chan) [Orabug: 29357977]

  - bnxt_en: reduce timeout on initial HWRM calls (Andy
    Gospodarek) [Orabug: 29357977]

  - bnxt_en: Fix NULL pointer dereference at bnxt_free_irq.
    (Michael Chan) [Orabug: 29357977]

  - bnxt_en: Check valid VNIC ID in bnxt_hwrm_vnic_set_tpa.
    (Michael Chan) [Orabug: 29357977]

  - bnxt_en: Do not modify max IRQ count after RDMA driver
    requests/frees IRQs. (Michael Chan) [Orabug: 29357977]

  - mm: cleancache: fix corruption on missed inode
    invalidation (Pavel Tikhomirov) [Orabug: 29364670]
    (CVE-2018-16862)

  - l2tp: fix reading optional fields of L2TPv3 (Jacob Wen)
    [Orabug: 29368048]

  - net/packet: fix a race in packet_bind and
    packet_notifier (Eric Dumazet) [Orabug: 29385593]
    (CVE-2018-18559)

  - ext4: verify the depth of extent tree in
    ext4_find_extent (Theodore Ts'o) [Orabug: 29396712]
    (CVE-2018-10877) (CVE-2018-10877)

  - blk-mq: Do not invoke .queue_rq for a stopped queue
    (Bart Van Assche) [Orabug: 28766011]

  - uek-rpm: use multi-threaded xz compression for rpms
    (Alexander Burmashev) [Orabug: 29323635]

  - uek-rpm: optimize find-requires usage (Alexander
    Burmashev) [Orabug: 29323635]

  - find-debuginfo.sh: backport parallel files procession
    (Alexander Burmashev) [Orabug: 29323635]

  - KVM: SVM: Add MSR-based feature support for serializing
    LFENCE (Tom Lendacky) [Orabug: 29335274]

  - Enable RANDOMIZE_BASE (John Haxby) [Orabug: 29305587]

  - slub: make ->cpu_partial unsigned (Alexey Dobriyan)
    [Orabug: 28620592]

  - dtrace: support kernels built with RANDOMIZE_BASE (Kris
    Van Hees) [Orabug: 29204005]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-March/000931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1a93dc7"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9568");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.26.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.26.1.el6uek")) flag++;

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
