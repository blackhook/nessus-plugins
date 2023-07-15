#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-635.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136458);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/26");

  script_cve_id("CVE-2020-6457", "CVE-2020-6458", "CVE-2020-6459", "CVE-2020-6460", "CVE-2020-6461", "CVE-2020-6462");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-635)");
  script_summary(english:"Check for the openSUSE-2020-635 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

Opera was updated to version 68.0.3618.63

  - CHR-7889 Update chromium on desktop-stable-81-3618 to
    81.0.4044.122

  - CHR-7896 Update chromium on desktop-stable-81-3618 to
    81.0.4044.129

  - DNA-85287 Set standard spacing for Yandex prompt

  - DNA-85416 [Mac] Animation of tab insert is glitchy on
    slow machines

  - DNA-85568 Verify API for triggering &ldquo;unread&rdquo;
    mode with Instagram.

  - DNA-86027 Present Now not working in google meet after
    canceling it once

  - DNA-86028 Add a back and forward button in the Instagram
    panel

  - DNA-86029 Investigate and implement re-freshing of the
    instagram panel content

  - Update chromium to 81.0.4044.122 fixes CVE-2020-6458,
    CVE-2020-6459, CVE-2020-6460

  - Update chromium to 81.0.4044.129 fixes CVE-2020-6461,
    CVE-2020-6462

Update to version 68.0.3618.56

  - DNA-85256 [Win] Cookies section on site pages is white
    in dark mode

  - DNA-85474 [Mac] Dragging tabs to the left with hidden
    sidebar is broken

  - DNA-85771 DNS-over-HTTPS example in settings is wrong

  - DNA-85976 Change page display time when navigating from
    opera:startpage

  - CHR-7878 Update chromium on desktop-stable-81-3618 to
    81.0.4044.113 (CVE-2020-6457)

  - DNA-78158 PATCH-1272 should be removed

  - DNA-84721 Weather widget is overlapped when &lsquo;Use
    bigger tiles&rsquo;

  - DNA-85246 Implement 0-state dialog and onboarding

  - DNA-85354 O-menu is misplaced when opened with maximized
    opera

  - DNA-85405 Add link to Privacy Policy on the 0-state
    dialog

  - DNA-85409 Ask for geolocation EULA once

  - DNA-85426 Crash at opera::DownloadActionButton::Update()

  - DNA-85454 Add id&rsquo;s to elements for testing

  - DNA-85493 Add &ldquo;Show Weather&rdquo; toggle to
    &ldquo;Start Page&rdquo; section in Easy Setup

  - DNA-85501 Set timestamps in geolocation exception record

  - DNA-85514 Add fallback when geolocation fails

  - DNA-85713 Report consent for geolocation on start page

  - DNA-85753 Fetch news configuration from new endpoint

  - DNA-85798 Incorrect padding in Search in Tabs window

  - DNA-85801 Disable notification on instagram panel

  - DNA-85809 Update instagram icon in the Sidebar Setup

  - DNA-85854 Change Instagram panel size, to fit desktop
    version

  - Complete Opera 68.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-68/

Update to version 67.0.3575.137

  - CHR-7852 Update chromium on desktop-stable-80-3575 to
    80.0.3987.163

  - DNA-82540 Crash at
    remote_cocoa::NativeWidgetNSWindowBridge::
    SetVisibilityState(remote_cocoa::mojom::WindowVisibility
    State)

  - DNA-84951 New PiP is completely black for some 2 GPU
    setups

  - DNA-85284 Chrome &ldquo;Open link in same tab, pop-up as
    tab [Free]&rdquo; extension is no longer working in
    Opera

  - DNA-85415 [Mac] Inspect Popup not working

  - DNA-85530 Create API for displaying and triggering
    &ldquo;unread&rdquo; mode for messengers from in-app

  - DNA-85537 Let addons.opera.com interact with sidebar
    messengers

Update to version 67.0.3575.115

  - CHR-7833 Update chromium on desktop-stable-80-3575 to
    80.0.3987.149

  - DNA-74423 [Mac] Search/Copy popup stuck on top left of
    screen

  - DNA-82975 Crash at
    blink::DocumentLifecycle::EnsureStateAtMost
    (blink::DocumentLifecycle::LifecycleState)

  - DNA-83834 Crash at base::MessagePumpNSApplication::
    DoRun (base::MessagePump::Delegate*)

  - DNA-84632 macOS 10.15.2 fail on creating testlist.json

  - DNA-84713 Switching through tabs broken when using
    workspaces"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-68/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");
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

if ( rpm_check(release:"SUSE15.1", reference:"opera-68.0.3618.63-lp151.2.15.1") ) flag++;

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
