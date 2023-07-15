#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1713.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141905);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-15959", "CVE-2020-15960", "CVE-2020-15961", "CVE-2020-15962", "CVE-2020-15963", "CVE-2020-15964", "CVE-2020-15965", "CVE-2020-15966", "CVE-2020-6556", "CVE-2020-6573", "CVE-2020-6574", "CVE-2020-6575", "CVE-2020-6576");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-1713)");
  script_summary(english:"Check for the openSUSE-2020-1713 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

opera was updated to version 71.0.3770.228

  - DNA-87466 Hide extensions icon is black in dark theme

  - DNA-88580 Implement search_in_tabs telemetry benchmark

  - DNA-88591 Allow to scroll down the Keyboards Shortcuts
    section with URL

  - DNA-88693 Random crash in SmartFilesBrowserTest

  - DNA-88793 change VPN disclaimer modal layout

  - DNA-88799 Only active workspaces and active messengers
    should be listed in keyboard shortcuts settings

  - DNA-88838 add automatic VPN connection preference
    setting

  - DNA-88870 Align VPN popup to new design

  - DNA-88900 Turn off Tutorials in Opera GX &ndash;
    implementation

  - DNA-88931 Add info about channel and product (OPR,
    OPRGX) to rollout requests

  - DNA-88940 Allow continue-shopping|booking-host-override
    switch to handle host and path

  - DNA-88946 Auto-connect VPN after browser startup only
    for existing VPN users

  - DNA-89009 Change URL for search-suggestions

  - DNA-89021 Make RH test driver pack to a separate archive

  - DNA-89150 Unhardcode &lsquo;From&rsquo; and
    &lsquo;To&rsquo; strings in Advanced History Search

  - DNA-89175 Desktop without a flow paring should not
    initialize in browser startup

Opera was updated to version 71.0.3770.198

  - CHR-8106 Update chromium on desktop-stable-85-3770 to
    85.0.4183.121

  - DNA-85648 Reconnecting Flow with iOS is unstable

  - DNA-87130 Spinner is stretched instead of clipped

  - DNA-87989 In Find in Page, &ldquo;No matches&rdquo;
    doesn&rsquo;t go away after deleting all text

  - DNA-88098 Data URLs entries should not open new tab
    after click on new history page

  - DNA-88267 Extra semicolon in Russian BABE translation

  - DNA-88312 [Win] Downloads file drag and drop
    doesn&rsquo;t work in Opera

  - DNA-88363 Add premium extension functionality

  - DNA-88580 Implement search_in_tabs telemetry benchmark

  - DNA-88611 Black font on a dark background in sync login
    dialog

  - DNA-88626 Disable #easy-files on desktop-stable-85-xxxx

  - DNA-88701 String &ldquo;Type a shortcut&rdquo; is
    hardcoded

  - DNA-88755 Crash at
    extensions::WebstoreOneClickInstallerUIImpl::
    RemoveAllInfobarsExcept(opera::ExtensionInstallInfoBarDe
    legate*)

  - DNA-88797 Change &lsquo;Register&rsquo; to
    &lsquo;Tab&rsquo; in German

  - DNA-88851 [History][Resized window] Button and date
    input look bad

  - DNA-88958 Crash at net::`anonymous
    namespace&rdquo;::Escape

  - The update to chromium 85.0.4183.121 fixes following
    issues :

  - CVE-2020-15960, CVE-2020-15961, CVE-2020-15962,
    CVE-2020-15963, CVE-2020-15965, CVE-2020-15966,
    CVE-2020-15964

  - Update to version 71.0.3770.148

  - CHR-8091 Update chromium on desktop-stable-85-3770 to
    85.0.4183.102

  - DNA-87785 [Mac] &ldquo;Alitools&rdquo; text in extension
    toolbar overlaps Install button

  - DNA-87935 Make SSD smaller by 25%

  - DNA-87963 Hidden Avira extension in avira_2 edition

  - DNA-88015 [MyFlow] Desktop doesn&rsquo;t show itself in
    devices list

  - DNA-88469 Add context menu options to configure
    shortcuts

  - DNA-88496 Define a/b test in ab_tests.json

  - DNA-88537 Don&rsquo;t filter out hashes from feature
    reference groups coming from rollout

  - DNA-88580 Implement search_in_tabs telemetry benchmark

  - DNA-88604 [History panel] Search bar covers the
    &ldquo;Clear browsing data&rdquo; button

  - DNA-88619 String &lsquo;Download complete&rsquo; is cut
    on download popup

  - DNA-88645 Remove option should not be available for last
    workspace

  - DNA-88718 [History panel] fix delete button overflow
    issue

  - The update to chromium 85.0.4183.102 fixes following
    issues :

  - CVE-2020-6573, CVE-2020-6574, CVE-2020-6575,
    CVE-2020-6576, CVE-2020-15959

  - Complete Opera 71.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-71/

  - Update to version 70.0.3728.144

  - CHR-8057 Update chromium on desktop-stable-84-3728 to
    84.0.4147.135

  - DNA-88027 [Mac] Downloads icon disappears when downloads
    popup is shown

  - DNA-88204 Crash at
    opera::DownloadItemView::OnMousePressed (ui::MouseEvent
    const&)

  - The update to chromium 84.0.4147.135 fixes following
    issues :

  - CVE-2020-6556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-71/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6556");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/26");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"opera-71.0.3770.228-lp151.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"opera-71.0.3770.228-lp152.2.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
