#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2178.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143498);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id("CVE-2020-16013", "CVE-2020-16017");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-2178)");
  script_summary(english:"Check for the openSUSE-2020-2178 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

  - Update to version 72.0.3815.400

  - DNA-88996 [Mac] Vertical spacing of sidebar items
    incorrect

  - DNA-89698 [Mac] text on bookmark bar not visible when
    application is not focused

  - DNA-89746 Add product-name switch to Opera launcher and
    installer

  - DNA-89779 Implement multi-window behavior for pinned
    Player

  - DNA-89924 Music continue to play after the disabling
    Player from Sidebar

  - DNA-89994 Fix progress bar shape and color

  - DNA-89995 Fix font sizes, weights and colors of text in
    control panel

  - DNA-90010 Payment Methods in Settings mention Google
    account

  - DNA-90022 [Mac][BigSur] Crash at
    -[BrowserWindowController
    window:willPositionSheet:usingRect:]

  - DNA-90025 Player stays in the autopause after reloading
    panel &ndash; part 2

  - DNA-90096 Sidebar click stat not collected for Player

  - DNA-90143 Adding a stat for Player sidebar clicks to the
    Avro schema

  - Update to version 72.0.3815.378

  - CHR-8192 Update chromium on desktop-stable-86-3815 to
    86.0.4240.198

  - DNA-86550 XHRUint8Array test time out

  - DNA-88631 Unintended volume drop

  - DNA-88708 [Snap] Inproper area snapped

  - DNA-88726 [Mac] Overlay &lsquo;pause&rsquo; icon when
    Opera auto-pauses the Player

  - DNA-88903 Detach video button should not be visible

  - DNA-88938 Make home page reflect service configuration

  - DNA-88943 Learn more link on home page doesnt work

  - DNA-88944 Apple Music service slow to open

  - DNA-88948 Fetch audio focus request id from MediaSession

  - DNA-88949 Detach video button missing

  - DNA-88966 No accessiblity titles for services icons in
    home page

  - DNA-88967 Investigate creating a single
    BrowserSidebarModel instance

  - DNA-88995 Overlay &ldquo;pause&rdquo; is displayed when
    it shouldn&rsquo;t

  - DNA-89017 Error when signing out of YouTube Music

  - DNA-89054 Audio is not resumed when muting audio in tab

  - DNA-89094 DCHECK when pressing Reload button

  - DNA-89095 Manage service data through PlayerService

  - DNA-89100 [Player] Crash &ndash; many scenarios

  - DNA-89187 Reload button doesn&rsquo;t work properly

  - DNA-89189 Update icons and buttons

  - DNA-89217 Enable #player-service on developer stream

  - DNA-89220 SidebarCarouselTests.* failing

  - DNA-89230 Crash at v8::Context::Enter()

  - DNA-89244 Define default widths per service

  - DNA-89245 Improve Spotify logo layout in home page
    buttons

  - DNA-89248 Crash at
    opera::WebPageBrowserSidebarItemContentViewViews
    ::UpdatePlayerService()

  - DNA-89278 [Sidebar] No notification for downloads and
    workspaces

  - DNA-89285 [Engine] Unable to launch skype with Opera

  - DNA-89292 Do not block page loads waiting for sitecheck
    data

  - DNA-89316 Should be able to navigate directly to
    playerServices section in settings

  - DNA-89339 Make popup appear with tooltip-like behavior

  - DNA-89340 Implement control panel looks in light and
    dark mode

  - DNA-89341 Make the control panel buttons work

  - DNA-89342 Add support for the DNA to the rollout system

  - DNA-89344 Show Music Service icon in the control panel

  - DNA-89360 Make &lsquo;Settings&rsquo; menu entry go to
    settings

  - DNA-89366 Make opera://feedback/babe attachable by the
    webdriver

  - DNA-89419 Crash at base::Value::GetAsDictionary
    (base::DictionaryValue const**) const

  - DNA-89469 Autopause does not work

  - DNA-89477 Do not wait with starting the player if the
    interrupting session is short

  - DNA-89480 Crash when hovering player panel

  - DNA-89484 Crash at
    base::internal::CheckedObserverAdapter
    ::IsMarkedForRemoval()

  - DNA-89489 Put control panel behind feature flag

  - DNA-89514 Implement feedback button for Player

  - DNA-89516 Do not auto-pause the Player when there is no
    sound

  - DNA-89553 Make the control panel show current song

  - DNA-89557 No accessibility title for rating and close
    buttons inside feedback dialog

  - DNA-89561 Make the control panel show artwork that
    represents current track

  - DNA-89575 Handle longer track and artist names

  - DNA-89577 Make progress bar work correctly

  - DNA-89630 Controler pop-up is too high (and service logo
    too)

  - DNA-89634 Panel width is reset when it shouldn&rsquo;t

  - DNA-89654 Request higher resolution images for HiDPI

  - DNA-89655 Enable #player-service-control-panel on
    Developer stream

  - DNA-89671 No accessiblity titles for control panel
    elements

  - DNA-89672 String change &ldquo;A world of
    music&hellip;&rdquo;

  - DNA-89679 Player &mdash; don&rsquo;t show control panel
    when Player in sidebar is opened

  - DNA-89722 Album cover arts are not visible

  - DNA-89766 Address bar does not respond to actions

  - DNA-89776 Control panel does not disappear after
    hovering elsewhere

  - DNA-89778 Implement multi-window behavior when no Player
    is pinned

  - DNA-89795 Player is enable after Opera restart (when in
    Settings was turned off)

  - DNA-89803 Artwork is cropped to the right

  - DNA-89812 Sidebar panel should hide when toggle between
    windows

  - DNA-89820 Incorrect music services for Philippines

  - DNA-89846 Do not show the control panel if there is
    nothing to show

  - DNA-89878 Clarify notification dot for messengers

  - DNA-89901 [Mac][Player] Zombie crash at exit

  - DNA-89952 Crash at
    opera::BrowserSidebarPlayerItemContentViewViews
    ::LoadPlayerServiceURL()

  - DNA-89964 Player stays in the autopause after reloading
    panel

  - DNA-89971 Multi window behaviour is not respected
    anymore

  - DNA-89976 Disallow docking for Player

  - DNA-89986 Enable #player-service and
    #player-service-control-panel on all streams

  - DNA-90006 Change services order in RU/UA/BY

  - The update to chromium 86.0.4240.198 fixes following
    issues: CVE-2020-16013, CVE-2020-16017"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16017");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");
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

if ( rpm_check(release:"SUSE15.1", reference:"opera-72.0.3815.400-lp151.2.36.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"opera-72.0.3815.400-lp152.2.24.1") ) flag++;

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
