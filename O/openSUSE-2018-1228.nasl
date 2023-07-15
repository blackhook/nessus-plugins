#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1228.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118343);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10906");

  script_name(english:"openSUSE Security Update : fuse (openSUSE-2018-1228)");
  script_summary(english:"Check for the openSUSE-2018-1228 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for fuse fixes the following issues :

  - CVE-2018-10906: fusermount was vulnerable to a
    restriction bypass when SELinux is active. This allowed
    non-root users to mount a FUSE file system with the
    'allow_other' mount option regardless of whether
    'user_allow_other' is set in the fuse configuration. An
    attacker may use this flaw to mount a FUSE file system,
    accessible by other users, and trick them into accessing
    files on that file system, possibly causing Denial of
    Service or other unspecified effects (bsc#1101797)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101797"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected fuse packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fuse-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfuse2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libulockmgr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libulockmgr1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.0", reference:"fuse-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"fuse-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"fuse-debugsource-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"fuse-devel-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"fuse-devel-static-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfuse2-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libfuse2-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libulockmgr1-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libulockmgr1-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libfuse2-32bit-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libfuse2-32bit-debuginfo-2.9.7-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fuse / fuse-debuginfo / fuse-debugsource / fuse-devel / etc");
}
