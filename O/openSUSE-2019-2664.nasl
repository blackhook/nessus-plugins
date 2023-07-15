#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2664.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(131922);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-13720", "CVE-2019-13721");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2019-0698");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2019-2664)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for opera fixes the following issues :

Opera was updated to version 65.0.3467.62

  - CHR-7658 Update chromium on desktop-stable-78-3467 to
    78.0.3904.108

  - DNA-81387 Remove support for old bundle structure in
    signing scripts

  - DNA-81675 Update widevine signature localisation in
    signed packages

  - DNA-81884 [Advanced content blocking] Ads are blocked
    for whitelisted page in Incognito

  - DNA-82230 [Mac] URL is not correctly aligned when the
    Geolocation is ON

  - DNA-82368 Generating diffs for unsinged packages
    doesn&rsquo;t work

  - DNA-82414 Wrong number of trackers displayed just after
    deactivating adblocker

  - DNA-82470 [Linux] Snap package doesn&rsquo;t recognise
    GNOME 3.24 platform snap connection

  - DNA-82473 https://www.nba.com/standings not working with
    AdBlocker enabled

  - DNA-82484 Update content blocking icon

  - DNA-82485 [Mac 10.15] Opera installer error at the end
    of installation process

  - DNA-82508 [Adblocker] Predefault lists can not be
    unchecked

  - DNA-82557 Address bar dropdown launches HTTP GETs for
    every autocomplete

  - DNA-82596 Do not block first-party
    &lsquo;trackers&rsquo;

  - DNA-82616 Settings &ndash; Tracker Blocker &ndash; Add
    &ldquo;Learn more&rdquo; link

  - DNA-82626 [Win] High CPU usage due to media indicator
    animation

  - DNA-82647 Tab icons mixed after Tab closing

  - DNA-82742 Pages won&rsquo;t load after closing private
    mode

  - DNA-82768 Mark also the reference group in
    &ldquo;exp&rdquo; header for DNA-81658

  - DNA-82840 Disable favicon fetching for typed URLs

Complete Opera 65.0 changelog at :

https://blogs.opera.com/desktop/changelog-for-65/

Update to version 64.0.3417.92

  - DNA-81358 Wrong key color on extension popup in dark
    mode

  - DNA-82208 Cherry-pick CVE-2019-13721 and CVE-2019-13720

Update to version 64.0.3417.83

  - DNA-79676 Use FFmpegDemuxer to demux ADTS

  - DNA-81010 Spinner takes a lot of cpu

  - DNA-81385 Keys on some popups in dark mode can&rsquo;t
    be hovered

  - DNA-81494 [Mac] Snap onboarding doesn&rsquo;t appear
    while the icon still flashes

  - DNA-82003 Restore legacy path for AudioFileReader

  - DNA-82019 Enable #ffmpeg-demuxer-everywhere by default
    in developer

  - DNA-82028 Enable #ffmpeg-demuxer-everywhere by default
    in stable on macOS

Update to version 64.0.3417.73

  - CHR-7598 Update chromium on desktop-stable-77-3417 to
    77.0.3865.120

  - DNA-80049 The upper border of &ldquo;Add to bookmarks
    bar&rdquo; popup is cut off in white mode

  - DNA-80395 Menu popup borders in Settings are invisible
    in Dark mode

  - DNA-81263 Change the continue section buttons visibility
    as in description

  - DNA-81304 Crash at chrome::NewTab(Browser*)

  - DNA-81650 Easy Setup Style looks weird

  - DNA-81708 Missing dependency on
    //chrome/common:buildflags

  - DNA-81732 [Mac][Catalina] Cannot maximize a window after
    it&rsquo;s been minimized

  - DNA-81737 Renderer crash on
    https://codesandbox.io/s/vanilla-ts

  - DNA-81753 Pinned tab only remembered after next restart

  - DNA-81769 Investigate reports about slow speed dial
    loading in O64 blog comments

  - DNA-81859 [Mac 10.15] Crash whenever navigating to any
    page

  - DNA-81893 Get Personalised news on SpeedDials broken
    layout

Update to version 64.0.3417.61

  - DNA-80760 Sidebar Messenger icon update

  - DNA-81165 Remove sharing service

  - DNA-81211 [Advanced content blocking] Can not turn off
    ad blocking in private mode

  - DNA-81323 content_filter::RendererConfigProvider
    destroyed on wrong sequence

  - DNA-81487 [VPN disclaimer][da, ta] Text should be
    multiline

  - DNA-81545 opr-session entry for Google ads not working

  - DNA-81580 Speed dials&rsquo; colours change after Opera
    update

  - DNA-81597 [Adblocker] Google Ads link hides if clicking

  - DNA-81639 Widevine verification status is
    PLATFORM_TAMPERED

  - DNA-81237 [Advanced content blocking] noCoinis not
    enabled by default

  - DNA-81375 Adblocking_AddToWhitelist_Popup and
    Adblocking_RemoveFromWhitelist_Popup metric not recorded
    in stats

  - DNA-81413 Error in console when Start Page connects to
    My Flow

  - DNA-81435 Adjust VPN disclaimer to longer strings [de]

Update to version 64.0.3417.47

  - DNA-80531 [Reborn3] Unify Switches

  - DNA-80738 &ldquo;How to protect my privacy&rdquo; link

  - DNA-81162 Enable #advanced-content-blocking on developer
    stream

  - DNA-81202 Privacy Protection popup doesn&rsquo;t resize
    after enabling blockers

  - DNA-81230 [Mac] Drop support for 10.10

  - DNA-81280 Adjust button width to the shorter string

  - DNA-81295 Opera 64 translations

  - DNA-81346 Enable #advanced-content-blocking on all
    streams

  - DNA-81434 Turn on #new-vpn-flow in all streams

  - DNA-81436 Import translations from Chromium to O64

  - DNA-81460 Promote O64 to stable

  - DNA-81461 Snap onboarding is cut

  - DNA-81467 Integrate missing translations (Chinese, MS
    and TL) to O64/65

  - DNA-81489 Start page goes into infinite loop

Complete Opera 64.0 changelog at:
https://blogs.opera.com/desktop/changelog-for-64/

Update to version 63.0.3368.94

  - CHR-7516 Update chromium on master to 78.0.3887.7

  - DNA-80966 [Linux] Integrate a new key into our packages

Update to version 63.0.3368.88

  - DNA-79103 Saving link to bookmarks saves it to Other
    bookmarks folder

  - DNA-79455 Crash at views::MenuController::
    FindNextSelectableMenuItem(views::MenuItemView*, int,
    views:: MenuController::SelectionIncrementDirectionType,
    bool)

  - DNA-79579 Continuous packages using
    new_mac_bundle_structure do not run

  - DNA-79611 Update opauto_paths.py:GetResourcesDir

  - DNA-79621 Add support for new bundle structure to old
    autoupdate clients

  - DNA-79906 Fix package build

  - DNA-80131 Sign Opera Helper(GPU).app

  - DNA-80191 Fix
    opera_components/tracking_data/tracking_data_paths.cc

  - DNA-80638 Cherry-pick fix for CreditCardTest.
    UpdateFromImportedCard_ExpiredVerifiedCardUpdatedWithSam
    eName

  - DNA-80801 Very slow tab deletion process");
  script_set_attribute(attribute:"see_also", value:"https://blogs.opera.com/desktop/changelog-for-64/");
  script_set_attribute(attribute:"see_also", value:"https://blogs.opera.com/desktop/changelog-for-65/");
  script_set_attribute(attribute:"see_also", value:"https://codesandbox.io/s/vanilla-ts");
  script_set_attribute(attribute:"see_also", value:"https://www.nba.com/standings");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13721");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"opera-65.0.3467.62-lp151.2.9.1") ) flag++;

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
