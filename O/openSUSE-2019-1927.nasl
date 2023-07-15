#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1927.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128013);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");

  script_name(english:"openSUSE Security Update : zypper / libzypp and libsolv (openSUSE-2019-1927)");
  script_summary(english:"Check for the openSUSE-2019-1927 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libzypp and libsolv fixes the following issues :

Security issues fixed :

  - CVE-2018-20532: Fixed NULL pointer dereference at
    ext/testcase.c (function testcase_read) (bsc#1120629).

  - CVE-2018-20533: Fixed NULL pointer dereference at
    ext/testcase.c (function testcase_str2dep_complex) in
    libsolvext.a (bsc#1120630).

  - CVE-2018-20534: Fixed illegal address access at
    src/pool.h (function pool_whatprovides) in libsolv.a
    (bsc#1120631).

Fixed bugs and enhancements :

  - make cleandeps jobs on patterns work (bnc#1137977)

  - Fixed an issue where libsolv failed to build against
    swig 4.0 by updating the version to 0.7.5 (bsc#1135749). 

  - Virtualization host upgrade from SLES-15 to SLES-15-SP1
    finished with wrong product name shown up (bsc#1131823).

  - Copy pattern categories from the rpm that defines the
    pattern (fate#323785).

  - Enhance scanning /sys for modaliases (bsc#1130161).

  - Prevent SEGV if the application sets an empty TextLocale
    (bsc#1127026).

  - Handle libgpgme error when gpg key is not completely
    read and user hits CTRL + C (bsc#1127220).

  - Added a hint when registration codes have expired
    (bsc#965786).

  - Adds a better handling of an error when verifying any
    repository medium (bsc#1065022).

  - Will now only write type field when probing
    (bsc#1114908).

  - Fixes an issue where zypper has showed the info message
    'Installation aborted by user' while the installation
    was aborted by wicked (bsc#978193).

  - Suppresses reporting `/memfd:` pseudo files
    (bsc#1123843).

  - Fixes an issue where zypper was not able to install or
    uninstall packages when rpm is unavailable
    (bsc#1122471).

  - Fixes an issue where locks were ignored (bsc#1113296).

  - Simplify complex locks so zypper can display them
    (bsc#1112911).

  - zypper will now set `SYSTEMD_OFFLINE=1` during chrooted
    commits (bsc#1118758).

  - no-recommends: Nevertheless consider resolver namespaces
    (hardware, language,..supporting packages)
    (fate#325513).

  - Removes world-readable bit from /var/log/zypp
    (bsc#1099019).

  - Does no longer fail service-refresh on a empty
    repoindex.xml (bsc#1116840).

  - Fixes soname due to libsolv ABI changes (bsc#1115341).

  - Add infrastructure to flag specific packages to trigger
    a reboot needed hint (fate#326451).

This update for zypper 1.14.27 fixes the following issues :

  - bash-completion: add package completion for addlock
    (bsc#1047962)

  - bash-completion: fix incorrect detection of command
    names (bsc#1049826)

  - Offer to change the 'runSearchPackages' config option at
    the prompt (bsc#1119373, FATE#325599)

  - Prompt: provide a 'yes/no/always/never' prompt.

  - Prompt: support '#NUM' as answer to select the NUMth
    option...

  - Augeas: enable writing back changed option values (to
    ~/.zypper.conf)

  - removelocale: fix segfault

  - Move needs-restarting command to subpackage (fixes #254)

  - Allow empty string as argument (bsc#1125415)

  - Provide a way to delete cache for volatile repositories
    (bsc#1053177)

  - Adapt to boost-1.69 requiring explicit casts
    tribool->bool (fixes #255)

  - Show support status in info if not unknown (bsc#764147)

  - Fix installing plain rpm files with `zypper in`
    (bsc#1124897)

  - Show only required info in the summary in quiet mode
    (bsc#993025)

  - Stay with legacy behavior and return
    ZYPPER_EXIT_INF_REBOOT_NEEDED only for patches. We don't
    extend this return code to packages, although they may
    also carry the 'reboot-needed' attribute. The preferred
    way to test whether the system needs to be rebooted is
    `zypper needs-rebooting`. (openSUSE/zypper#237)

  - Skip repository on error (bsc#1123967)

  - New commands for locale management: locales addlocale
    removelocale Inspect and manipulate the systems
    `requested locales`, aka. the languages software
    packages should try support by installing translations,
    dictionaries and tools, as far as they are available.

  - Don't throw, just warn if options are repeated
    (bsc#1123865)

  - Fix detection whether stdout is a tty (happened too
    late)

  - Fix broken --plus-content switch (fixes bsc#1123681)

  - Fix broken --replacefiles switch (fixes bsc#1123137)

  - Extend zypper source-install (fixes bsc#663358)

  - Fix inconsistent results for search (bsc#1119873)

  - Show reboot hint in zypper ps and summary (fixes
    bsc#1120263)

  - Improve handling of partially locked packages
    (bsc#1113296)

  - Fix wrong default values in help text (bsc#1121611)

  - Fixed broken argument parsing for --reposd-dir
    (bsc#1122062)

  - Fix wrong zypp::indeterminate use (bsc#1120463)

  - CLI parser: fix broken initialization enforcing 'select
    by name' (bsc#1119820)

  - zypper.conf: [commit] autoAgreeWithLicenses (=false)
    (fixes #220)

  - locks: Fix printing of versioned locks (bsc#1112911)

  - locks: create and write versioned locks correctly
    (bsc#1112911)

  - patch: --with update may implicitly assume
    --with-optional (bsc#1102261)

  - no-recommends: Nevertheless consider resolver namespaces
    (hardware, language,..supporting packages) (FATE#325513)

  - Optionally run 'zypper search-packages' after 'search'
    (FATE#325599)

  - zypper.conf: Add [search]runSearchPackages config
    variable.

  - Don't iterate twice on --no-cd (bsc#1111319)

  - zypper-log: Make it Python 3 compatible

  - man: mention /etc/zypp/needreboot config file
    (fate#326451, fixes #140)

  - Add `needs-restarting` shell script and manpage
    (fate#326451)

  - Add zypper needs-rebooting command (fate#326451)

  - Introduce new zypper command framefork. Migrated
    commands so far: addlock addrepo addservice clean
    cleanlocks modifyrepo modifyservice ps refresh
    refresh-services removelock removerepo removeservice
    renamerepo repos services

  - MediaChangeReport: fix https URLs causing 2 prompts on
    error (bsc#1110542)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=663358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=764147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/323785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326451"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zypper / libzypp and libsolv packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-ncurses-pkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-ncurses-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-ncurses-pkg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-ncurses-pkg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-qt-pkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-qt-pkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-qt-pkg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyui-qt-pkg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitGlib-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-pkg-bindings-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-aptitude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-needs-restarting");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-backend-zypp-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-backend-zypp-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-branding-upstream-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-debugsource-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-devel-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-devel-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-gstreamer-plugin-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-gstreamer-plugin-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-gtk3-module-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-gtk3-module-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"PackageKit-lang-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpackagekit-glib2-18-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpackagekit-glib2-18-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpackagekit-glib2-devel-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-ncurses-pkg-debugsource-2.48.5.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-ncurses-pkg-devel-2.48.5.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-ncurses-pkg8-2.48.5.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-ncurses-pkg8-debuginfo-2.48.5.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-qt-pkg-debugsource-2.45.15.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-qt-pkg-devel-2.45.15.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-qt-pkg8-2.45.15.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libyui-qt-pkg8-debuginfo-2.45.15.2-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-PackageKitGlib-1_0-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"yast2-pkg-bindings-4.0.13-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"yast2-pkg-bindings-debuginfo-4.0.13-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"yast2-pkg-bindings-debugsource-4.0.13-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zypper-aptitude-1.14.28-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zypper-log-1.14.28-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"zypper-needs-restarting-1.14.28-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpackagekit-glib2-18-32bit-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpackagekit-glib2-18-32bit-debuginfo-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpackagekit-glib2-devel-32bit-1.1.10-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-debugsource-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-demo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-demo-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-devel-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-devel-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-tools-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libsolv-tools-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libzypp-17.12.0-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libzypp-debuginfo-17.12.0-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libzypp-debugsource-17.12.0-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libzypp-devel-17.12.0-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"perl-solv-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"perl-solv-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python-solv-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python-solv-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-solv-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"python3-solv-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ruby-solv-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"ruby-solv-debuginfo-0.7.5-lp150.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"zypper-1.14.28-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"zypper-debuginfo-1.14.28-lp150.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"zypper-debugsource-1.14.28-lp150.2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-backend-zypp / etc");
}
