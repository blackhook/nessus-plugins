#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-829.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150259);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2021-829)");
  script_summary(english:"Check for the openSUSE-2021-829 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

Update to version 76.0.4017.154

  - CHR-8420 Update chromium on desktop-stable-90-4017 to
    90.0.4430.212

  - DNA-92411 Bookmarks breadcrumbs wrong color when pressed
    in dark mode

  - DNA-92587 Sync settings: &ldquo;Use old password&rdquo;
    button doesn&rsquo;t work

  - DNA-92672 Make it possible for agent to inject scripts
    into startpage

  - DNA-92712 Add SD reload API

  - DNA-93190 The bookmark can&rsquo;t be opened in
    Workspace 5-6

  - DNA-93247 Reopen last closed tab shortcut opens random
    tab on new window

  - DNA-93294 Binary diff for opera_browser.dll is not
    created on 32-bit builds

  - DNA-93313 Add opauto test to cover DNA-93190

  - DNA-93368 Fix an error in Polish translation

  - DNA-93408 [Windows] widevine_cdm_component_installer
    does not compile on desktop-stable-90-4017

  - The update to chromium 90.0.4430.212 fixes following
    issues: CVE-2021-30506, CVE-2021-30507, CVE-2021-30508,
    CVE-2021-30509, CVE-2021-30510, CVE-2021-30511,
    CVE-2021-30512, CVE-2021-30513, CVE-2021-30514,
    CVE-2021-30515, CVE-2021-30516, CVE-2021-30517,
    CVE-2021-30518, CVE-2021-30519, CVE-2021-30520

Update to version 76.0.4017.123

  - DNA-91951 SkipAds click by default with Adblocker on
    Youtube

  - DNA-92293 [Mac] Crash at
    opera::BrowserWindowImpl::Cleanup()

  - DNA-92714 [Mac] Worskpace switching lags with lot of
    tabs

  - DNA-92847 DCHECK at tab_lifecycle_unit_source.cc:145

  - DNA-92860 [Windows] Fix issues when running buildsign
    script with Python 3

  - DNA-92879 Fix issues when running buildsign script with
    Python 3

  - DNA-92938 opera://activity/ page ignores workspaces

  - DNA-93015 [Player] Panel is too narrow

  - DNA-93044 Remove unnecessary question mark in Cashback
    string in Polish

  - DNA-93070 [Search Tabs] Selecting items with cursor keys
    skips over content matches

  - DNA-93122 Use input in builddiff.py

  - DNA-93175 Fix running repacking"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30520");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opera-76.0.4017.154-lp152.2.49.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
