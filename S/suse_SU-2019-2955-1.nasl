#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2955-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130953);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-12207", "CVE-2018-20126", "CVE-2019-11135", "CVE-2019-12068", "CVE-2019-14378", "CVE-2019-15890");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : qemu (SUSE-SU-2019:2955-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

qemu was updated to v3.1.1.1, a stable, bug-fix-only release, which
includes 2 fixes we already carry, as well as one additional use-
after-free fix in slirp. (CVE-2018-20126 bsc#1119991, CVE-2019-14378
bsc#1143794, and CVE-2019-15890 bsc#1149811 respectively)

Security issues fixed :

CVE-2019-12068: Fixed potential DOS in lsi scsi controller emulation
(bsc#1146873)

CVE-2019-11135: Expose taa-no 'feature', indicating CPU does not have
the TSX Async Abort vulnerability. (bsc#1152506)

CVE-2018-12207: Expose pschange-mc-no 'feature', indicating CPU does
not have the page size change machine check vulnerability
(bsc#1117665)

Other issues fixed: Change how this bug gets fixed (bsc#1144087)

Disable file locking in the Xen PV disk backend to avoid locking
issues with PV domUs during migration. The issues triggered by the
locking can not be properly handled in libxl. The locking introduced
in qemu-2.10 was removed again in qemu-4.0. (bsc#1079730, bsc#1098403,
bsc#1111025, bsc#1145427, bsc#1145774)

Feature support for vfio-ccw dasd ipl (bsc#1145379 jira-SLE-6132)

Additional hardware instruction support for s390, also update qemu
linux headers to 5.2-rc1 (bsc#1145436 jira-SLE-6237)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12207/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20126/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12068/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15890/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192955-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34dce43a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-2955=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2955=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2955=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-oss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-alsa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-alsa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-oss-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-oss-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-pa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-audio-pa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-s390-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-s390-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-ui-curses-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-ui-curses-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-ui-gtk-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-ui-gtk-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-x86-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"qemu-x86-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-alsa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-alsa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-oss-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-oss-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-pa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-audio-pa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-s390-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-ui-curses-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-ui-curses-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-ui-gtk-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-ui-gtk-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-x86-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"qemu-x86-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-arm-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-arm-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-curl-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-curl-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-dmg-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-dmg-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-iscsi-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-iscsi-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-rbd-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-rbd-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-ssh-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-block-ssh-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-debugsource-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-extra-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-extra-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-guest-agent-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-guest-agent-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-kvm-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-lang-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-linux-user-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-linux-user-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-linux-user-debugsource-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-ppc-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-ppc-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-tools-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"qemu-tools-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"qemu-s390-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"qemu-s390-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-alsa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-alsa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-oss-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-oss-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-pa-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-audio-pa-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-ui-curses-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-ui-curses-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-ui-gtk-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-ui-gtk-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-x86-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"qemu-x86-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-arm-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-arm-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-block-dmg-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-block-dmg-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-debugsource-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-extra-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-extra-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-linux-user-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-linux-user-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-linux-user-debugsource-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-ppc-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-ppc-debuginfo-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-tools-3.1.1.1-9.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"qemu-tools-debuginfo-3.1.1.1-9.6.2")) flag++;


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
