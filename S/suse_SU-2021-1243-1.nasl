#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1243-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148755);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2020-12829", "CVE-2020-15469", "CVE-2020-25084", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27616", "CVE-2020-27617", "CVE-2020-27821", "CVE-2020-28916", "CVE-2020-29129", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20257", "CVE-2021-3416");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : qemu (SUSE-SU-2021:1243-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

CVE-2020-12829: Fix OOB access in sm501 device emulation (bsc#1172385)

CVE-2020-25723: Fix use-after-free in usb xhci packet handling
(bsc#1178934)

CVE-2020-25084: Fix use-after-free in usb ehci packet handling
(bsc#1176673)

CVE-2020-25625: Fix infinite loop (DoS) in usb hcd-ohci emulation
(bsc#1176684)

CVE-2020-25624: Fix OOB access in usb hcd-ohci emulation (bsc#1176682)

CVE-2020-27617: Fix guest triggerable assert in shared network
handling code (bsc#1178174)

CVE-2020-28916: Fix infinite loop (DoS) in e1000e device emulation
(bsc#1179468)

CVE-2020-29443: Fix OOB access in atapi emulation (bsc#1181108)

CVE-2020-27821: Fix heap overflow in MSIx emulation (bsc#1179686)

CVE-2020-15469: Fix NULL pointer deref. (DoS) in mmio ops
(bsc#1173612)

CVE-2021-20257: Fix infinite loop (DoS) in e1000 device emulation
(bsc#1182577)

CVE-2021-3416: Fix OOB access (stack overflow) in rtl8139 NIC
emulation (bsc#1182968)

CVE-2021-3416: Fix OOB access (stack overflow) in other NIC emulations
(bsc#1182968)

CVE-2020-27616: Fix OOB access in ati-vga emulation (bsc#1178400)

CVE-2020-29129: Fix OOB access in SLIRP ARP/NCSI packet processing
(bsc#1179466, CVE-2020-29130, bsc#1179467)

Fix package scripts to not use hard-coded paths for temporary working
directories and log files (bsc#1182425)

Add split-provides through forsplits/13 to cover updates of SLE15-SP2
to SLE15-SP3, and openSUSE equivalents (bsc#1184064)

Added a few more usability improvements for our git packaging workflow

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173612"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1178400"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181108"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12829/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15469/"
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
    value:"https://www.suse.com/security/cve/CVE-2020-27616/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27617/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27821/"
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
    value:"https://www.suse.com/security/cve/CVE-2021-20257/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-3416/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211243-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afef34d2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE MicroOS 5.0 :

zypper in -t patch SUSE-SUSE-MicroOS-5.0-2021-1243=1

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-1243=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1243=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25624");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-app-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/02");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-alsa-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-alsa-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-pa-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-audio-pa-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-curses-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-curses-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-gtk-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-ui-gtk-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-x86-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"qemu-x86-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"qemu-s390-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"s390x", reference:"qemu-s390-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-curl-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-curl-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-iscsi-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-iscsi-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-rbd-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-rbd-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-ssh-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-block-ssh-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-debugsource-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-guest-agent-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-guest-agent-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-kvm-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-lang-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-tools-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-tools-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-ui-spice-app-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"qemu-ui-spice-app-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-debuginfo-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-debugsource-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-tools-4.2.1-11.16.3")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"qemu-tools-debuginfo-4.2.1-11.16.3")) flag++;


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
