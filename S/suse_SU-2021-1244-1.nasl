#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1244-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148757);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/08");

  script_cve_id("CVE-2020-11947", "CVE-2020-12829", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13765", "CVE-2020-14364", "CVE-2020-15469", "CVE-2020-15863", "CVE-2020-16092", "CVE-2020-25084", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27617", "CVE-2020-28916", "CVE-2020-29129", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20181", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-20257", "CVE-2021-3416");

  script_name(english:"SUSE SLES15 Security Update : qemu (SUSE-SU-2021:1244-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

Fix OOB access in sm501 device emulation (CVE-2020-12829, bsc#1172385)

Fix OOB access possibility in MegaRAID SAS 8708EM2 emulation
(CVE-2020-13362 bsc#1172383)

Fix use-after-free in usb xhci packet handling (CVE-2020-25723,
bsc#1178934)

Fix use-after-free in usb ehci packet handling (CVE-2020-25084,
bsc#1176673)

Fix OOB access in usb hcd-ohci emulation (CVE-2020-25624, bsc#1176682)

Fix infinite loop (DoS) in usb hcd-ohci emulation (CVE-2020-25625,
bsc#1176684)

Fix guest triggerable assert in shared network handling code
(CVE-2020-27617, bsc#1178174)

Fix infinite loop (DoS) in e1000e device emulation (CVE-2020-28916,
bsc#1179468)

Fix OOB access in atapi emulation (CVE-2020-29443, bsc#1181108)

Fix NULL pointer deref. (DoS) in mmio ops (CVE-2020-15469,
bsc#1173612)

Fix infinite loop (DoS) in e1000 device emulation (CVE-2021-20257,
bsc#1182577)

Fix OOB access (stack overflow) in rtl8139 NIC emulation
(CVE-2021-3416, bsc#1182968)

Fix OOB access (stack overflow) in other NIC emulations
(CVE-2021-3416)

Fix OOB access in SLIRP ARP/NCSI packet processing (CVE-2020-29129,
bsc#1179466, CVE-2020-29130, bsc#1179467)

Fix NULL pointer dereference possibility (DoS) in MegaRAID SAS 8708EM2
emulation (CVE-2020-13659 bsc#1172386

Fix OOB access in iscsi (CVE-2020-11947 bsc#1180523)

Fix OOB access in vmxnet3 emulation (CVE-2021-20203 bsc#1181639)

Fix buffer overflow in the XGMAC device (CVE-2020-15863 bsc#1174386)

Fix DoS in packet processing of various emulated NICs (CVE-2020-16092
bsc#1174641)

Fix OOB access while processing USB packets (CVE-2020-14364
bsc#1175441)

Fix package scripts to not use hard-coded paths for temporary working
directories and log files (bsc#1182425)

Fix potential privilege escalation in virtfs (CVE-2021-20181
bsc#1182137)

Drop the 'ampersand 0x25 shift altgr' line in pt-br keymap file
(bsc#1129962)

Fix migration failure with error message: 'error while loading state
section id 3(ram) (bsc#1154790)

Fix OOB access possibility in ES1370 audio device emulation
(CVE-2020-13361 bsc#1172384)

Fix OOB access in ROM loading (CVE-2020-13765 bsc#1172478)

Fix OOB access in ARM interrupt handling (CVE-2021-20221 bsc#1181933)

Tweaks to spec file for better formatting, and remove not needed
BuildRequires for e2fsprogs-devel and libpcap-devel

Use '%service_del_postun_without_restart' instead of
'%service_del_postun' to avoid 'Failed to try-restart
qemu-ga@.service' error while updating the qemu-guest-agent.
(bsc#1178565)

Fix OOB access in sm501 device emulation (CVE-2020-12829, bsc#1172385)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1129962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-11947/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12829/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13361/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13659/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13765/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15469/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15863/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-16092/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25084/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25624/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25625/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25723/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27617/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-28916/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-29129/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-29130/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-29443/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20181/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20203/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20221/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-20257/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-3416/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211244-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0dd14e75"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-1244=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-1244=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1244=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1244=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20181");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-curl-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-curl-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-iscsi-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-iscsi-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-rbd-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-rbd-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-ssh-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-block-ssh-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-debugsource-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-guest-agent-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-guest-agent-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-kvm-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-lang-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-s390-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-s390-debuginfo-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-tools-2.11.2-9.43.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-tools-debuginfo-2.11.2-9.43.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
