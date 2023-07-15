#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0032.
#

include("compat.inc");

if (description)
{
  script_id(139442);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-19054", "CVE-2020-12888", "CVE-2020-14416");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0032)");
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

  - uek-rpm: Add OL6 shim conflict for new signing key (Eric
    Snowberg) [Orabug: 31688239] - Revert 'certs: Add
    Oracle's new X509 cert into the kernel keyring' (Eric
    Snowberg) [Orabug: 31688223] - blk-mq: don't overwrite
    rq->mq_ctx (Jens Axboe) [Orabug: 31457304] - blk-mq:
    mark ctx as pending at batch in flush plug path (Ming
    Lei) [Orabug: 31457304]

  - scsi: qla2xxx: Fix stuck session in GNL (Quinn Tran)
    [Orabug: 31561461] - scsi: qla2xxx: Serialize session
    free in qlt_free_session_done (Quinn Tran) [Orabug:
    31561461] - scsi: qla2xxx: v2: Change abort wait_loop
    from msleep to wait_event_timeout (Giridhar Malavali)
    [Orabug: 26932683] - scsi: qla2xxx: v2: Move ABTS code
    behind qpair (Quinn Tran) [Orabug: 31517449] - ocfs2:
    change slot number type s16 to u16 (Junxiao Bi) [Orabug:
    31027042] - ocfs2: fix value of OCFS2_INVALID_SLOT
    (Junxiao Bi) [Orabug: 31027042] - ocfs2: fix panic on
    nfs server over ocfs2 (Junxiao Bi) [Orabug: 31027042] -
    ocfs2: load global_inode_alloc (Junxiao Bi) [Orabug:
    31027042] - ocfs2: avoid inode removal while nfsd is
    accessing it (Junxiao Bi) [Orabug: 31027042] -
    block_dev: don't test bdev->bd_contains when it is not
    stable (NeilBrown) [Orabug: 31554143] - KVM: x86: Remove
    spurious semicolon (Joao Martins) [Orabug: 31584727]

  - media: rc: prevent memory leak in cx23888_ir_probe
    (Navid Emamdoost) [Orabug: 31351672] (CVE-2019-19054)

  - vfio/pci: Fix SR-IOV VF handling with MMIO blocking
    (Alex Williamson) [Orabug: 31439671] (CVE-2020-12888)

  - vfio/pci: Mask buggy SR-IOV VF INTx support (Alex
    Williamson) [Orabug: 31439671] (CVE-2020-12888)

  - vfio-pci: Invalidate mmaps and block MMIO access on
    disabled memory (Alex Williamson) [Orabug: 31439671]
    (CVE-2020-12888) (CVE-2020-12888)

  - vfio/pci: Pull BAR mapping setup from read-write path
    (Alex Williamson) [Orabug: 31439671] (CVE-2020-12888)

  - vfio_pci: Enable memory accesses before calling
    pci_map_rom (Eric Auger) [Orabug: 31439671]
    (CVE-2020-12888)

  - vfio-pci: Fault mmaps to enable vma tracking (Alex
    Williamson) [Orabug: 31439671] (CVE-2020-12888)

  - vfio/type1: Support faulting PFNMAP vmas (Alex
    Williamson) [Orabug: 31439671] (CVE-2020-12888)

  - mm: bring in additional flag for fixup_user_fault to
    signal unlock (Dominik Dingel) [Orabug: 31439671]
    (CVE-2020-12888)

  - vfio/type1: Fix VA->PA translation for PFNMAP VMAs in
    vaddr_get_pfn (Sean Christopherson) [Orabug: 31439671]
    (CVE-2020-12888)

  - x86/mitigations: reset default value for
    srbds_mitigation (Mihai Carabas) [Orabug: 31514993] -
    x86/cpu: clear X86_BUG_SRBDS before late loading (Mihai
    Carabas) [Orabug: 31514993] - x86/mitigations: update
    MSRs on all CPUs for SRBDS (Mihai Carabas) [Orabug:
    31514993] - Revert 'x86/efi: Request desired alignment
    via the PE/COFF headers' (Matt Fleming) [Orabug:
    31602576]

  - can, slip: Protect tty->disc_data in write_wakeup and
    close with RCU (Richard Palethorpe) [Orabug: 31516085]
    (CVE-2020-14416)

  - scsi: qla2xxx: Fix warning in qla2x00_async_iocb_timeout
    [Orabug: 31530589] - scsi: qla2xxx: Fix NULL pointer
    access for fcport structure (Quinn Tran) [Orabug:
    31530589]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-August/000992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccf50329"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14416");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.41.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.41.4.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
