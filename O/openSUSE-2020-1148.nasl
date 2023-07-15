#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1148.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139357);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517", "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521", "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525", "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6536");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-1148)");
  script_summary(english:"Check for the openSUSE-2020-1148 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

  - Update to version 70.0.3728.71

  - DNA-86267 Make `Recently closed tabs` appearance
    consistent with `Search for open tabs`.

  - DNA-86988 Opera 70 translations

  - DNA-87530 Zen news leads not loading

  - DNA-87636 Fix displaying folder icon for closed windows
    in recently closed list

  - DNA-87682 Replace Extensions icon in toolbar with icon
    from sidebar

  - DNA-87756 Extend chrome.sessions.getRecentlyClosed with
    information about last active tab in window.

  - DNA-87778 Crash at opera::InstantSearchViewViews::
    ~InstantSearchViewViews()

  - DNA-87815 Change affiliate links for AliExpress Search

  - Update to version 70.0.3728.59

  - CHR-8010 Update chromium on desktop-stable-84-3728 to
    84.0.4147.89

  - DNA-87019 The video image does not respond to the
    pressing after closed the &ldquo;Quit Opera?&rdquo;
    dialog

  - DNA-87342 Fix right padding in settings > weather
    section

  - DNA-87427 Remove unneeded information from the
    requests&rsquo; diagnostics

  - DNA-87560 Crash at views::Widget::GetNativeView()

  - DNA-87561 Crash at CRYPTO_BUFFER_len

  - DNA-87599 Bypass VPN for default search engines
    doesn&rsquo;t work

  - DNA-87611 Unittests fails on declarativeNetRequest and
    declarativeNetRequestFeedback permissions

  - DNA-87612 [Mac] Misaligned icon in address bar

  - DNA-87619 [Win/Lin] Misaligned icon in address bar

  - DNA-87716 [macOS/Windows] Crash when Search in tabs is
    open and Opera is minimized

  - DNA-87749 Crash at
    opera::InstantSearchSuggestionLineView::
    SetIsHighlighted(bool)

  - The update to chromium 84.0.4147.89 fixes following
    issues :

  - CVE-2020-6510, CVE-2020-6511, CVE-2020-6512,
    CVE-2020-6513, CVE-2020-6514, CVE-2020-6515,
    CVE-2020-6516, CVE-2020-6517, CVE-2020-6518,
    CVE-2020-6519, CVE-2020-6520, CVE-2020-6521,
    CVE-2020-6522, CVE-2020-6523, CVE-2020-6524,
    CVE-2020-6525, CVE-2020-6526, CVE-2020-6527,
    CVE-2020-6528, CVE-2020-6529, CVE-2020-6530,
    CVE-2020-6531, CVE-2020-6533, CVE-2020-6534,
    CVE-2020-6535, CVE-2020-6536

  - Complete Opera 70.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-70/

  - Update to version 69.0.3686.77

  - DNA-84207 New Yubikey enrollment is not working

  - DNA-87185 Lost translation

  - DNA-87382 Integrate scrolling to top of the feed with
    the existing scroll position restoration

  - DNA-87535 Sort out news on start page state

  - DNA-87588 Merge &ldquo;Prevent pointer from being sent
    in the clear over SCTP&rdquo; to desktop-stable-83-3686

  - Update to version 69.0.3686.57

  - DNA-86682 Title case in Russian translation

  - DNA-86807 Title case in O69 BR Portuguese translation

  - DNA-87104 Right click context menu becomes scrollable
    sometimes

  - DNA-87376 Search in tabs opens significantly slower in
    O69

  - DNA-87505 [Welcome Pages][Stats] Session stats for
    Welcome and Upgrade pages

  - DNA-87535 Sort out news on start page state"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-70/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/06");
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

if ( rpm_check(release:"SUSE15.1", reference:"opera-70.0.3728.71-lp151.2.24.1") ) flag++;

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
