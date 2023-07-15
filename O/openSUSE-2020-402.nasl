#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-402.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135006);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/30");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-402)");
  script_summary(english:"Check for the openSUSE-2020-402 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opera fixes the following issues :

Update to version 67.0.3575.97

  - DNA-84063 Open URL in new tab with &lsquo;Go to web
    address&rsquo; in search/copy popup and right mouse
    click context menu

  - DNA-84780 Search in Search and Copy popup opens tab in
    wrong position from popup window

  - DNA-84786 Crash at
    Browser::PasteAndGo(std::__1::basic_string const&,
    WindowOpenDisposition)

  - DNA-84815 Crash at TabStripModel::GetIndexOfWebContents
    (content::WebContents const*)

  - DNA-84937 [Mac] Workspace switching is slow with a lot
    of tabs opened

  - DNA-85159 Sidebar-setup not refreshed correctly after
    signing out from sync

Update to version 67.0.3575.79

  - CHR-7804 Update chromium on desktop-stable-80-3575 to
    80.0.3987.132

  - DNA-83766 Opera Ad Blocker extension state is not
    updated when changing it

  - DNA-83966 Enable kFeatureSuggestionScoringImproved on
    all the streams

  - DNA-84159 Settings &ndash; list of workspaces in the
    settings isn&rsquo;t updated after reordering

  - DNA-84396 Inline autocomplete not working when SD
    becomes the top-scored suggestion

  - DNA-84711 Wrong autocomplete address for https sites

  - DNA-84741 No amazon partner extension displayed

  - DNA-84743 Crash at
    ExtensionsToolbarContainer::UndoPopOut()

  - DNA-84776 Bookmarks not fully displayed in Bookmarks
    Panel

  - DNA-84817 Crash at
    Browser::IsSearchAndCopyPopupEnabled()

  - DNA-84836 Broken video playback in some cases

  - DNA-84837 Audio decoder broken although available on
    Windows 7

  - DNA-84860 [Mac] Address field not highlighted on hover

  - DNA-84889 [desktop-stable-80-3575] There&rsquo;re no
    basic settings

  - DNA-84910 Fix output type selection of SW H.264 decoder

  - DNA-84938 Prepare stable build with Yx 05 edition

  - DNA-84969 Address bar dropdown launches HTTP GETs for
    every autocomplete

Update to version 67.0.3575.53

  - CHR-7792 Update chromium on desktop-stable-80-3575 to
    80.0.3987.122

  - DNA-84024 &lsquo;Save all Tabs in Speed Dial
    Folder&rsquo; doesn&rsquo;t work on main context menu

  - DNA-84056 Submenus are not scrollable

  - DNA-84061 Expanded bookmark menu overlaps the whole
    toolbar

  - DNA-84277 Whole text should be visible

  - DNA-84412 Dragging tab to different place activates
    another tab

  - DNA-84492 Disable any notifications for &ldquo;default
    browser&rdquo; from sweetlabs builds

  - DNA-84691 Crash when trying to open sidebar context menu

  - Update to version 67.0.3575.31

  - DNA-84077 Hide seek and timer controls in video pop-out
    for YouTube live streams

  - DNA-84639 Promote O67 to stable

  - Complete Opera 67.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-67/

Update to version 66.0.3515.103

  - DNA-83528 UnpackTest.CanUnpackTarXzFile test fails on
    OSX 10.15+

  - DNA-83568 Add test driver perftests

  - DNA-84335 [Linux] Widevine is not working due to changed
    path of libwidevinecdm.so

  - DNA-84439 Opera extensions update requests are sent to
    chrome instead of opera servers

Update to version 66.0.3515.72

  - DNA-79691 Unable to play video on Netflix right after
    Opera installation

  - DNA-82102 Wrong cursor and X color of the search fields
    on Bookmark/History sidebar panels

  - DNA-82722 Google Translator blocks PDF viewer

  - DNA-83407 Crash at static void `anonymous
    namespace&rdquo;::PureCall()

  - DNA-83530 Bad colors in Personal news when dark theme
    turned on

  - DNA-83531 Dragging speed dial root folders in bookmarks
    sidebar makes duplicates

  - DNA-83542 Fix background tabs loading issues

  - DNA-83806 Crash at opera::RichHintDisplayHandlerViews::
    OnWidgetDestroying(views::Widget*)

  - DNA-83882 Crash at base::Value::Clone()

  - DNA-84007 Accessibility elements visible on pages after
    first navigation on Mac

Update to version 66.0.3515.44

  - CHR-7734 Update chromium on desktop-stable-79-3515 to
    79.0.3945.130

  - DNA-82635 [Mac] Fix crash when opening power save popup
    twice

  - DNA-83587 Fix Crash at
    opera::ThumbnailHelper::ThumbnailRequest::PopNextFrameTo
    Paint()

  - DNA-83698 Unregister extensions keybindings when sidebar
    is hidden

  - DNA-83757 Stop making thumbnail after history onboarding
    will show

Update to version 66.0.3515.36

  - CHR-7717 Update chromium on desktop-stable-79-3515 to
    79.0.3945.117

  - DNA-81359 Translate &ldquo;Speed Dials&rdquo; folder in
    bookmarks panel

  - DNA-82627 Unify & streamline tooltip color processing
    across Opera.

  - DNA-82800 Enable
    kFeatureTurnOnFeaturesDownloadedByInstallerOnUpdates on
    all streams

  - DNA-83190 Record SwitchToFullSite events on icon clicks.

  - DNA-83496 Check if history-panel is enabled before
    showing onboarding.

  - DNA-83545 Fix a crash in adblocker rule update

  - DNA-83583 [Mac] Bookmark popup too bright in dark mode

  - DNA-83608 Set &ldquo;plat&rdquo; metadata in crash
    reports from Linux.

Update to version 66.0.3515.27

  - DNA-82683 Bookmarks menu is not readable in dark mode
    after hovering

  - DNA-83139 [macOS] screenshot is resized

  - DNA-83204 [Mac] Anchor onboarding widget to history icon
    on sidebar

  - DNA-83205 [Mac] Popup looks bad with mode change

  - DNA-83351 Enable feature on stable/beta

  - DNA-83366 [Mac] Onboarding popup doesn&rsquo;t follow
    the browser window

  - DNA-83402 Promote O66 to stable

  - Complete Opera 66.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-66/

Update to version 65.0.3467.69

  - DNA-82647 Tab icons mixed after Tab closing

  - DNA-82919 Update wrapper to skip package types when
    creating repo

  - DNA-82967 [Mac] Opera crashes on dragging the SSL icon
    on the URL Bar"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-66/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-67/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"opera-67.0.3575.97-lp151.2.12.1") ) flag++;

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
