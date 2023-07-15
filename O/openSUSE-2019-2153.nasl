#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129094);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662", "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666", "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670", "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675", "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679", "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683", "CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5874", "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877", "CVE-2019-5878", "CVE-2019-5879", "CVE-2019-5880", "CVE-2019-5881");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-2153)");
  script_summary(english:"Check for the openSUSE-2019-2153 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

Security issues fixed :

  - CVE-2019-5870: Fixed a use-after-free in media.
    (boo#1150425)

  - CVE-2019-5871: Fixed a heap overflow in Skia.
    (boo#1150425)

  - CVE-2019-5872: Fixed a use-after-free in Mojo
    (boo#1150425)

  - CVE-2019-5874: Fixed a behavior that made external URIs
    trigger other browsers. (boo#1150425)

  - CVE-2019-5875: Fixed a URL bar spoof via download
    redirect. (boo#1150425)

  - CVE-2019-5876: Fixed a use-after-free in media
    (boo#1150425)

  - CVE-2019-5877: Fixed an out-of-bounds access in V8.
    (boo#1150425)

  - CVE-2019-5878: Fixed a use-after-free in V8.
    (boo#1150425)

  - CVE-2019-5879: Fixed an extension issue that allowed the
    bypass of a same origin policy. (boo#1150425)

  - CVE-2019-5880: Fixed a SameSite cookie bypass.
    (boo#1150425)

  - CVE-2019-5881: Fixed an arbitrary read in SwiftShader.
    (boo#1150425)

  - CVE-2019-13659: Fixed an URL spoof. (boo#1150425)

  - CVE-2019-13660: Fixed a full screen notification
    overlap. (boo#1150425)

  - CVE-2019-13661: Fixed a full screen notification spoof.
    (boo#1150425)

  - CVE-2019-13662: Fixed a CSP bypass. (boo#1150425)

  - CVE-2019-13663: Fixed an IDN spoof. (boo#1150425)

  - CVE-2019-13664: Fixed a CSRF bypass. (boo#1150425)

  - CVE-2019-13665: Fixed a multiple file download
    protection bypass. (boo#1150425)

  - CVE-2019-13666: Fixed a side channel weakness using
    storage size estimate. (boo#1150425)

  - CVE-2019-13667: Fixed a URI bar spoof when using
    external app URIs. (boo#1150425)

  - CVE-2019-13668: Fixed a global window leak via console.
    (boo#1150425)

  - CVE-2019-13669: Fixed an HTTP authentication spoof.
    (boo#1150425)

  - CVE-2019-13670: Fixed a V8 memory corruption in regex.
    (boo#1150425)

  - CVE-2019-13671: Fixed a dialog box that failed to show
    the origin. (boo#1150425)

  - CVE-2019-13673: Fixed a cross-origin information leak
    using devtools. (boo#1150425)

  - CVE-2019-13674: Fixed an IDN spoofing opportunity.
    (boo#1150425)

  - CVE-2019-13675: Fixed an error that allowed extensions
    to be disabled by trailing slash. (boo#1150425)

  - CVE-2019-13676: Fixed a mistakenly shown Google URI in
    certificate warnings. (boo#1150425)

  - CVE-2019-13677: Fixed a lack of isolation in Chrome web
    store origin. (boo#1150425)

  - CVE-2019-13678: Fixed a download dialog spoofing
    opportunity. (boo#1150425)

  - CVE-2019-13679: Fixed a the necessity of a user gesture
    for printing. (boo#1150425)

  - CVE-2019-13680: Fixed an IP address spoofing error.
    (boo#1150425)

  - CVE-2019-13681: Fixed a bypass on download restrictions.
    (boo#1150425)

  - CVE-2019-13682: Fixed a site isolation bypass.
    (boo#1150425)

  - CVE-2019-13683: Fixed an exception leaked by devtools.
    (boo#1150425)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150425"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5878");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-77.0.3865.75-lp150.239.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-77.0.3865.75-lp150.239.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-77.0.3865.75-lp150.239.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-77.0.3865.75-lp150.239.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-77.0.3865.75-lp150.239.1", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
