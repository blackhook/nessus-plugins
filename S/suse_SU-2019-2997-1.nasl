#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2997-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131159);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2019-17594", "CVE-2019-17595");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ncurses (SUSE-SU-2019:2997-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ncurses fixes the following issues :

Security issues fixed :

CVE-2019-17594: Fixed a heap-based buffer over-read in the
_nc_find_entry function (bsc#1154036).

CVE-2019-17595: Fixed a heap-based buffer over-read in the fmt_entry
function (bsc#1154037).

Non-security issue fixed: Removed screen.xterm from terminfo database
(bsc#1103320).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17594/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17595/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192997-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2b58b87"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2997=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1:zypper in -t
patch SUSE-SLE-Module-Legacy-15-SP1-2019-2997=1

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2019-2997=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-2997=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-2997=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2997=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2997=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17595");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo-iterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo-screen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libncurses5-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libncurses5-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libncurses6-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libncurses6-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ncurses-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ncurses-devel-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ncurses5-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libncurses5-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libncurses5-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libncurses6-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libncurses6-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses-debugsource-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses-devel-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses-utils-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses-utils-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ncurses5-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"tack-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"tack-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"terminfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"terminfo-base-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"terminfo-iterm-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"terminfo-screen-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libncurses5-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libncurses5-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libncurses6-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libncurses6-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"ncurses-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"ncurses-devel-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libncurses5-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libncurses5-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libncurses6-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libncurses6-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses-debugsource-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses-devel-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses-utils-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses-utils-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ncurses5-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tack-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tack-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"terminfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"terminfo-base-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"terminfo-iterm-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"terminfo-screen-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libncurses6-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libncurses6-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ncurses-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ncurses-devel-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ncurses5-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libncurses6-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libncurses6-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ncurses-debugsource-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ncurses-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ncurses-devel-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ncurses-utils-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ncurses-utils-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"tack-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"tack-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"terminfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"terminfo-base-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"terminfo-iterm-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"terminfo-screen-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libncurses6-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libncurses6-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"ncurses-devel-32bit-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"ncurses-devel-32bit-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libncurses6-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libncurses6-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ncurses-debugsource-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ncurses-devel-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ncurses-devel-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ncurses-utils-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ncurses-utils-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tack-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tack-debuginfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"terminfo-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"terminfo-base-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"terminfo-iterm-6.1-5.6.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"terminfo-screen-6.1-5.6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncurses");
}
