#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0836-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(135166);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-19768", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2020:0836-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 15-SP1 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2020-8647: Fixed a use-after-free in the vc_do_resize function in
drivers/tty/vt/vt.c (bsc#1162929).

CVE-2020-8649: Fixed a use-after-free in the vgacon_invert_region
function in drivers/video/console/vgacon.c (bsc#1162931).

CVE-2020-8648: Fixed a use-after-free in the n_tty_receive_buf_common
function in drivers/tty/n_tty.c (bsc#1162928).

CVE-2020-9383: Fixed an out-of-bounds read due to improper error
condition check of FDC index (bsc#1165111).

CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function
in kernel/trace/blktrace.c (bnc#1159285).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1144333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1161951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1164078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1164507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1166735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-19768/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8647/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8648/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-9383/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200836-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3bd5f7b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1:zypper in -t patch
SUSE-SLE-Product-WE-15-SP1-2020-836=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-836=1

SUSE Linux Enterprise Module for Live Patching 15-SP1:zypper in -t
patch SUSE-SLE-Module-Live-Patching-15-SP1-2020-836=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1:zypper in -t
patch SUSE-SLE-Module-Legacy-15-SP1-2020-836=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-836=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-836=1

SUSE Linux Enterprise High Availability 15-SP1:zypper in -t patch
SUSE-SLE-Product-HA-15-SP1-2020-836=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9383");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kvmsmall-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kselftests-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-debug-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-default-livepatch-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-man-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-qa-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-syms-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-vanilla-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kselftests-kmp-default-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kselftests-kmp-default-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-debug-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"kernel-kvmsmall-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-default-livepatch-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-man-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-qa-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-syms-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-base-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-base-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-debugsource-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-vanilla-livepatch-devel-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kselftests-kmp-default-4.12.14-197.37.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kselftests-kmp-default-debuginfo-4.12.14-197.37.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
