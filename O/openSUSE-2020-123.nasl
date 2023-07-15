#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-123.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133344);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604");

  script_name(english:"openSUSE Security Update : git (openSUSE-2020-123)");
  script_summary(english:"Check for the openSUSE-2020-123 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for git fixes the following issues :

Security issues fixed :

  - CVE-2019-1349: Fixed issue on Windows, when submodules
    are cloned recursively, under certain circumstances Git
    could be fooled into using the same Git directory twice
    (bsc#1158787).

  - CVE-2019-19604: Fixed a recursive clone followed by a
    submodule update could execute code contained within the
    repository without the user explicitly having asked for
    that (bsc#1158795).

  - CVE-2019-1387: Fixed recursive clones that are currently
    affected by a vulnerability that is caused by too-lax
    validation of submodule names, allowing very targeted
    attacks via remote code execution in recursive clones
    (bsc#1158793).

  - CVE-2019-1354: Fixed issue on Windows that refuses to
    write tracked files with filenames that contain
    backslashes (bsc#1158792).

  - CVE-2019-1353: Fixed issue when run in the Windows
    Subsystem for Linux while accessing a working directory
    on a regular Windows drive, none of the NTFS protections
    were active (bsc#1158791).

  - CVE-2019-1352: Fixed issue on Windows was unaware of
    NTFS Alternate Data Streams (bsc#1158790).

  - CVE-2019-1351: Fixed issue on Windows mistakes drive
    letters outside of the US-English alphabet as relative
    paths (bsc#1158789).

  - CVE-2019-1350: Fixed incorrect quoting of command-line
    arguments allowed remote code execution during a
    recursive clone in conjunction with SSH URLs
    (bsc#1158788).

  - CVE-2019-1348: Fixed the --export-marks option of
    fast-import is exposed also via the in-stream command
    feature export-marks=... and it allows overwriting
    arbitrary paths (bsc#1158785).

  - Fixes an issue where git send-email failed to
    authenticate with SMTP server (bsc#1082023)

Bug fixes :

  - Add zlib dependency, which used to be provided by
    openssl-devel, so that package can compile successfully
    after openssl upgrade to 1.1.1. (bsc#1149792).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158795"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Authen-SASL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Net-SMTP-SSL");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"git-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-arch-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-core-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-core-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-credential-gnome-keyring-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-credential-libsecret-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-credential-libsecret-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-cvs-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-daemon-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-daemon-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-debugsource-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-email-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-gui-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-p4-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-svn-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-svn-debuginfo-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"git-web-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gitk-2.16.4-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-Authen-SASL-2.16-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-Net-SMTP-SSL-1.04-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-arch / git-core / git-core-debuginfo / etc");
}
