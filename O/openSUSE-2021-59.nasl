#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-59.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145340);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2017-9271");

  script_name(english:"openSUSE Security Update : libzypp / zypper (openSUSE-2021-59)");
  script_summary(english:"Check for the openSUSE-2021-59 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libzypp, zypper fixes the following issues :

Update zypper to version 1.14.41

Update libzypp to 17.25.4

  - CVE-2017-9271: Fixed information leak in the log file
    (bsc#1050625 bsc#1177583)

  - RepoManager: Force refresh if repo url has changed
    (bsc#1174016)

  - RepoManager: Carefully tidy up the caches. Remove
    non-directory entries. (bsc#1178966)

  - RepoInfo: ignore legacy type= in a .repo file and let
    RepoManager probe (bsc#1177427).

  - RpmDb: If no database exists use the _dbpath configured
    in rpm. Still makes sure a compat symlink at
    /var/lib/rpm exists in case the configures _dbpath is
    elsewhere. (bsc#1178910)

  - Fixed update of gpg keys with elongated expire date
    (bsc#179222)

  - needreboot: remove udev from the list (bsc#1179083)

  - Fix lsof monitoring (bsc#1179909)

yast-installation was updated to 4.2.48 :

  - Do not cleanup the libzypp cache when the system has low
    memory, incomplete cache confuses libzypp later
    (bsc#1179415)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179909"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libzypp / zypper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yast2-installation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-aptitude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-needs-restarting");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libzypp-17.25.5-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libzypp-debuginfo-17.25.5-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libzypp-debugsource-17.25.5-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libzypp-devel-17.25.5-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"yast2-installation-4.2.48-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-1.14.41-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-aptitude-1.14.41-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-debuginfo-1.14.41-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-debugsource-1.14.41-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-log-1.14.41-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zypper-needs-restarting-1.14.41-lp152.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / libzypp-debuginfo / libzypp-debugsource / libzypp-devel / etc");
}
