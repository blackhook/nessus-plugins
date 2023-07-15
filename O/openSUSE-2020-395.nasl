#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-395.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135161);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2012-6708", "CVE-2015-9251", "CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255", "CVE-2020-8130");

  script_name(english:"openSUSE Security Update : ruby2.5 (openSUSE-2020-395)");
  script_summary(english:"Check for the openSUSE-2020-395 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ruby2.5 toversion 2.5.7 fixes the following issues:
&#9; ruby 2.5 was updated to version 2.5.7 

  - CVE-2020-8130: Fixed a command injection in intree copy
    of rake (bsc#1164804).

  - CVE-2019-16255: Fixed a code injection vulnerability of
    Shell#[] and Shell#test (bsc#1152990).

  - CVE-2019-16254: Fixed am HTTP response splitting in
    WEBrick (bsc#1152992).

  - CVE-2019-15845: Fixed a null injection vulnerability of
    File.fnmatch and File.fnmatch? (bsc#1152994).

  - CVE-2019-16201: Fixed a regular expression denial of
    service of WEBrick Digest access authentication
    (bsc#1152995).

  - CVE-2012-6708: Fixed an XSS in JQuery

  - CVE-2015-9251: Fixed an XSS in JQuery

  - Fixed unit tests (bsc#1140844)

  - Removed some unneeded test files (bsc#1162396).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164804"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ruby2.5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8130");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libruby2_5-2_5-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libruby2_5-2_5-debuginfo-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-debuginfo-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-debugsource-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-devel-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-devel-extra-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-doc-ri-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-stdlib-2.5.7-lp151.4.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby2.5-stdlib-debuginfo-2.5.7-lp151.4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby2_5-2_5 / libruby2_5-2_5-debuginfo / ruby2.5 / etc");
}
