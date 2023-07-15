#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0054.
#

include("compat.inc");

if (description)
{
  script_id(143454);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/07");

  script_cve_id("CVE-2017-9605", "CVE-2020-16166");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0054)");
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

  - qla2xxx: disable target reset during link reset and
    update version (Quinn Tran) [Orabug: 32095664] - scsi:
    qla2xxx: Fix early srb free on abort (Quinn Tran)
    [Orabug: 32095664] - scsi: qla2xxx: Fix comment in
    MODULE_PARM_DESC in qla2xxx (Masanari Iida) [Orabug:
    32095664] - scsi: qla2xxx: Enable Async TMF processing
    [Orabug: 32095664] - qla2xxx: tweak debug message for
    task management path (Quinn Tran) [Orabug: 32095664] -
    scsi: qla2xxx: Fix hang when issuing nvme disconnect-all
    in NPIV (Arun Easi) [Orabug: 32095664] - scsi: qla2xxx:
    Fix fabric scan hang (Quinn Tran) [Orabug: 32095664] -
    scsi: qla2xxx: Do command completion on abort timeout
    (Quinn Tran) [Orabug: 32095664] - scsi: qla2xxx: Fix
    abort timeout race condition. (Quinn Tran) [Orabug:
    32095664] - scsi: qla2xxx: Fix race between switch cmd
    completion and timeout (Quinn Tran) [Orabug: 32095664] -
    scsi: qla2xxx: Add IOCB resource tracking (Quinn Tran)
    [Orabug: 32095664] - scsi: qla2xxx:v2: Fix double
    scsi_done for abort path (Quinn Tran) [Orabug: 32095664]
    - scsi: qla2xxx: v2 Fix a race condition between
    aborting and completing a SCSI command (Bart Van Assche)
    [Orabug: 32095664] - scsi: qla2xxx: Really fix
    qla2xxx_eh_abort (Bart Van Assche) [Orabug: 32095664] -
    scsi: qla2xxx: v2 Reject
    EH_[abort|device_reset|target_request] (Quinn Tran)
    [Orabug: 32095664] - scsi: qla2xxx: v2: Fix race
    conditions in the code for aborting SCSI commands (Bart
    Van Assche) [Orabug: 32095664]

  - IB/ipoib: Arm 'send_cq' to process completions in due
    time (Gerd Rausch) [Orabug: 31512608]

  - block: Move part of bdi_destory to del_gendisk as
    bdi_unregister. (Jan Kara) [Orabug: 32124131] - kernel:
    add panic_on_taint (Rafael Aquini) [Orabug: 32138039]

  - drm/vmwgfx: Make sure backup_handle is always valid
    (Sinclair Yeh) [Orabug: 31352076] (CVE-2017-9605)

  - random32: move the pseudo-random 32-bit definitions to
    prandom.h (Linus Torvalds) [Orabug: 31698086]
    (CVE-2020-16166)

  - random32: remove net_rand_state from the latent entropy
    gcc plugin (Linus Torvalds) [Orabug: 31698086]
    (CVE-2020-16166)

  - random: fix circular include dependency on arm64 after
    addition of percpu.h (Willy Tarreau) [Orabug: 31698086]
    (CVE-2020-16166)

  - random32: update the net random state on interrupt and
    activity (Willy Tarreau) [Orabug: 31698086]
    (CVE-2020-16166)

  - x86/kvm: move kvm_load/put_guest_xcr0 into atomic
    context (WANG Chao) [Orabug: 32021856] - kvm: x86: do
    not leak guest xcr0 into host interrupt handlers (David
    Matlack) [Orabug: 32021856]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-December/001007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d523adc2"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.45.6.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.45.6.el6uek")) flag++;

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
