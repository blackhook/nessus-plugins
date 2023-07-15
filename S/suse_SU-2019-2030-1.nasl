#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2030-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127759);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : zypper, libzypp / libsolv (SUSE-SU-2019:2030-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libzypp and libsolv fixes the following issues :

Security issues fixed :

CVE-2018-20532: Fixed NULL pointer dereference at ext/testcase.c
(function testcase_read) (bsc#1120629).

CVE-2018-20533: Fixed NULL pointer dereference at ext/testcase.c
(function testcase_str2dep_complex) in libsolvext.a (bsc#1120630).

CVE-2018-20534: Fixed illegal address access at src/pool.h (function
pool_whatprovides) in libsolv.a (bsc#1120631).

Fixed bugs and enhancements: make cleandeps jobs on patterns work
(bnc#1137977)

Fixed an issue where libsolv failed to build against swig 4.0 by
updating the version to 0.7.5 (bsc#1135749).

Virtualization host upgrade from SLES-15 to SLES-15-SP1 finished with
wrong product name shown up (bsc#1131823).

Copy pattern categories from the rpm that defines the pattern
(fate#323785).

Enhance scanning /sys for modaliases (bsc#1130161).

Prevent SEGV if the application sets an empty TextLocale
(bsc#1127026).

Handle libgpgme error when gpg key is not completely read and user
hits CTRL + C (bsc#1127220).

Added a hint when registration codes have expired (bsc#965786).

Adds a better handling of an error when verifying any repository
medium (bsc#1065022).

Will now only write type field when probing (bsc#1114908).

Fixes an issue where zypper has showed the info message 'Installation
aborted by user' while the installation was aborted by wicked
(bsc#978193).

Suppresses reporting `/memfd:` pseudo files (bsc#1123843).

Fixes an issue where zypper was not able to install or uninstall
packages when rpm is unavailable (bsc#1122471).

Fixes an issue where locks were ignored (bsc#1113296).

Simplify complex locks so zypper can display them (bsc#1112911).

zypper will now set `SYSTEMD_OFFLINE=1` during chrooted commits
(bsc#1118758).

no-recommends: Nevertheless consider resolver namespaces (hardware,
language,..supporting packages) (fate#325513).

Removes world-readable bit from /var/log/zypp (bsc#1099019).

Does no longer fail service-refresh on a empty repoindex.xml
(bsc#1116840).

Fixes soname due to libsolv ABI changes (bsc#1115341).

Add infrastructure to flag specific packages to trigger a reboot
needed hint (fate#326451).

This update for zypper 1.14.27 fixes the following issues:
bash-completion: add package completion for addlock (bsc#1047962)

bash-completion: fix incorrect detection of command names
(bsc#1049826)

Offer to change the 'runSearchPackages' config option at the prompt
(bsc#1119373, FATE#325599)

Prompt: provide a 'yes/no/always/never' prompt.

Prompt: support '#NUM' as answer to select the NUMth option...

Augeas: enable writing back changed option values (to ~/.zypper.conf)

removelocale: fix segfault

Move needs-restarting command to subpackage (fixes #254)

Allow empty string as argument (bsc#1125415)

Provide a way to delete cache for volatile repositories (bsc#1053177)

Adapt to boost-1.69 requiring explicit casts tribool->bool (fixes
#255)

Show support status in info if not unknown (bsc#764147)

Fix installing plain rpm files with `zypper in` (bsc#1124897)

Show only required info in the summary in quiet mode (bsc#993025)

Stay with legacy behavior and return ZYPPER_EXIT_INF_REBOOT_NEEDED
only for patches. We don't extend this return code to packages,
although they may also carry the 'reboot-needed' attribute. The
preferred way to test whether the system needs to be rebooted is
`zypper needs-rebooting`. (openSUSE/zypper#237)

Skip repository on error (bsc#1123967)

New commands for locale management: locales addlocale removelocale
Inspect and manipulate the systems `requested locales`, aka. the
languages software packages should try support by installing
translations, dictionaries and tools, as far as they are available.

Don't throw, just warn if options are repeated (bsc#1123865)

Fix detection whether stdout is a tty (happened too late)

Fix broken --plus-content switch (fixes bsc#1123681)

Fix broken --replacefiles switch (fixes bsc#1123137)

Extend zypper source-install (fixes bsc#663358)

Fix inconsistent results for search (bsc#1119873)

Show reboot hint in zypper ps and summary (fixes bsc#1120263)

Improve handling of partially locked packages (bsc#1113296)

Fix wrong default values in help text (bsc#1121611)

Fixed broken argument parsing for --reposd-dir (bsc#1122062)

Fix wrong zypp::indeterminate use (bsc#1120463)

CLI parser: fix broken initialization enforcing 'select by name'
(bsc#1119820)

zypper.conf: [commit] autoAgreeWithLicenses {=false} (fixes #220)

locks: Fix printing of versioned locks (bsc#1112911)

locks: create and write versioned locks correctly (bsc#1112911)

patch: --with update may implicitly assume --with-optional
(bsc#1102261)

no-recommends: Nevertheless consider resolver namespaces (hardware,
language,..supporting packages) (FATE#325513)

Optionally run 'zypper search-packages' after 'search' (FATE#325599)

zypper.conf: Add [search]runSearchPackages config variable.

Don't iterate twice on --no-cd (bsc#1111319)

zypper-log: Make it Python 3 compatible

man: mention /etc/zypp/needreboot config file (fate#326451, fixes
#140)

Add `needs-restarting` shell script and manpage (fate#326451)

Add zypper needs-rebooting command (fate#326451)

Introduce new zypper command framefork. Migrated commands so far:
addlock addrepo addservice clean cleanlocks modifyrepo modifyservice
ps refresh refresh-services removelock removerepo removeservice
renamerepo repos services

MediaChangeReport: fix https URLs causing 2 prompts on error
(bsc#1110542)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1130161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=663358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=764147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=978193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=993025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20532/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20533/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20534/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192030-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6949bd7b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2019-2030=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2030=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2030=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-2030=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2030=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2030=1

SUSE Linux Enterprise Installer 15:zypper in -t patch
SUSE-SLE-INSTALLER-15-2019-2030=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-backend-zypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-backend-zypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:PackageKit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpackagekit-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpackagekit-glib2-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-ncurses-pkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-ncurses-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-ncurses-pkg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-ncurses-pkg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-qt-pkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-qt-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-qt-pkg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyui-qt-pkg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-PackageKitGlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-pkg-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-pkg-bindings-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-pkg-bindings-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"libsolv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsolv-debugsource-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsolv-demo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsolv-demo-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-ncurses-pkg-debugsource-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-ncurses-pkg8-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-ncurses-pkg8-debuginfo-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-qt-pkg-debugsource-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-qt-pkg8-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libyui-qt-pkg8-debuginfo-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libzypp-debuginfo-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libzypp-debugsource-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libzypp-devel-doc-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-backend-zypp-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-backend-zypp-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-debugsource-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-devel-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"PackageKit-devel-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpackagekit-glib2-18-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpackagekit-glib2-18-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpackagekit-glib2-devel-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debugsource-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-demo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-demo-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-ncurses-pkg-debugsource-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-ncurses-pkg-devel-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-ncurses-pkg8-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-ncurses-pkg8-debuginfo-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-qt-pkg-debugsource-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-qt-pkg-devel-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-qt-pkg8-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libyui-qt-pkg8-debuginfo-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debuginfo-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debugsource-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-devel-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-devel-doc-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-PackageKitGlib-1_0-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"yast2-pkg-bindings-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"yast2-pkg-bindings-debuginfo-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"yast2-pkg-bindings-debugsource-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-1.14.28-3.18.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debuginfo-1.14.28-3.18.6")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debugsource-1.14.28-3.18.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsolv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsolv-debugsource-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsolv-demo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsolv-demo-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-ncurses-pkg-debugsource-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-ncurses-pkg8-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-ncurses-pkg8-debuginfo-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-qt-pkg-debugsource-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-qt-pkg8-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libyui-qt-pkg8-debuginfo-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libzypp-debuginfo-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libzypp-debugsource-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libzypp-devel-doc-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-backend-zypp-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-backend-zypp-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-debugsource-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-devel-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"PackageKit-devel-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpackagekit-glib2-18-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpackagekit-glib2-18-debuginfo-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpackagekit-glib2-devel-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debugsource-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-demo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-demo-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-ncurses-pkg-debugsource-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-ncurses-pkg-devel-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-ncurses-pkg8-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-ncurses-pkg8-debuginfo-2.48.5.2-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-qt-pkg-debugsource-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-qt-pkg-devel-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-qt-pkg8-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libyui-qt-pkg8-debuginfo-2.45.15.2-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debuginfo-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debugsource-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-devel-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-devel-doc-17.12.0-3.23.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-debuginfo-0.7.5-3.12.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-PackageKitGlib-1_0-1.1.10-4.10.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"yast2-pkg-bindings-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"yast2-pkg-bindings-debuginfo-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"yast2-pkg-bindings-debugsource-4.0.13-3.7.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-1.14.28-3.18.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debuginfo-1.14.28-3.18.6")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debugsource-1.14.28-3.18.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zypper / libzypp / libsolv");
}
