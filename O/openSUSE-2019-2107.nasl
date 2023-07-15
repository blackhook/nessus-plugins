#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2107.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131991);
  script_version("1.1");
  script_cvs_date("Date: 2019/12/12");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2019-2107)");
  script_summary(english:"Check for the openSUSE-2019-2107 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opera fixes the following issues :

Opera was updated to version 63.0.3368.66 :

  - CHR-7525 Update chromium on desktop-stable-76-3368 to
    76.0.3809.132

  - DNA-74031 Download indicator doesn&rsquo;t match
    progress

  - DNA-77042 Something went wrong message in crypto wallet
    in private window

  - DNA-79137 Crash at opera::installer::OptionsScreen::
    OnLanguageChanged()

  - DNA-79683 Installer crashes when showing progress

  - DNA-79757 Line divider under address bar disappears
    after opening and closing Bookmarks Bar

  - DNA-80012 Zoom popup appears each time clicking
    &lsquo;heart&rsquo; icon

  - DNA-80110 Bug when changing the install path in
    installer

  - DNA-80417 [assistant] Crash at
    opera::avro::event_driven::StatSenderImpl::NetworkThread
    :: SetTrafficAllowed(bool)

  - DNA-80422 Continue shopping section is too close to
    Speed Dial tiles when tiles are big

  - DNA-80463 Add shadow to shopping tiles

  - DNA-78143 Load async resources before rendering the page

  - DNA-79102 Make AU to be always server IPC endpoint when
    new AU logic is enabled

  - DNA-80193 Magnifying glass icon doesn&rsquo;t match the
    search box boundaries in settings and extensions

  - DNA-80416 Crash at
    opera::assistant::ProcessMonitorImpl::
    ObserveProcess(std::__1::basic_string const&,
    opera::assistant:: ProcessMonitor::Observer*)

  - DNA-79558 Add database for continue shopping feature

  - DNA-79560 Create hidden runtime flag #continue-shopping

  - DNA-79702 Create Continue Shopping service

  - DNA-79786 Fix database backend for deleting the partner
    offer

  - DNA-80193 Magnifying glass icon doesn&rsquo;t match the
    search box boundaries in settings and extensions

  - DNA-80237 Prevent data collection when feature is off

  - DNA-80244 Introduce another feature flag for changing
    the default value of folded state

  - DNA-79558 Add database for continue shopping feature

  - DNA-79560 Create hidden runtime flag #continue-shopping

  - DNA-79702 Create Continue Shopping service

  - DNA-79786 Fix database backend for deleting the partner
    offer

  - DNA-80193 Magnifying glass icon doesn&rsquo;t match the
    search box boundaries in settings and extensions

  - DNA-80237 Prevent data collection when feature is off

  - DNA-80244 Introduce another feature flag for changing
    the default value of folded state

  - DNA-79560 Create hidden runtime flag #continue-shopping

  - DNA-79702 Create Continue Shopping service

  - DNA-79786 Fix database backend for deleting the partner
    offer

  - DNA-80193 Magnifying glass icon doesn&rsquo;t match the
    search box boundaries in settings and extensions

  - DNA-80237 Prevent data collection when feature is off

  - DNA-80244 Introduce another feature flag for changing
    the default value of folded state

  - DNA-79063 Address bar icons are hardly visible in
    private window in light mode

  - DNA-79274 No warning notification on quitting Opera with
    multiple tabs open after update

  - DNA-80103 Investigate best ICECC_THREADS for faster Mac
    builds

  - DNA-80105 O63 translations (08.08.2019)

  - DNA-80219 DCHECK at
    ExtensionDownloader::HandleManifestResults

  - DNA-80330 [My Flow] The QR code and connection code is
    not visible for some people

  - DNA-79569 Don&rsquo;t provide default value for
    titleTextColor in opr.wallpapersAPI

  - DNA-80221 Change channel to &ldquo;stable&rdquo; in
    permissions features for wallpapersPrivate

  - DNA-80230 Promote O63 to stable"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"opera-63.0.3368.66-lp151.2.6.1") ) flag++;

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
