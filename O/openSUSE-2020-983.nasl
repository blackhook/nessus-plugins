#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-983.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138747);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2020-12402", "CVE-2020-12415", "CVE-2020-12416", "CVE-2020-12417", "CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-12421", "CVE-2020-12422", "CVE-2020-12423", "CVE-2020-12424", "CVE-2020-12425", "CVE-2020-12426");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-983)");
  script_summary(english:"Check for the openSUSE-2020-983 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox to version 78.0.1 ESR fixes the
following issues :

Security issues fixed :

  - CVE-2020-12415: AppCache manifest poisoning due to url
    encoded character processing (bsc#1173576).

  - CVE-2020-12416: Use-after-free in WebRTC
    VideoBroadcaster (bsc#1173576).

  - CVE-2020-12417: Memory corruption due to missing
    sign-extension for ValueTags on ARM64 (bsc#1173576).

  - CVE-2020-12418: Information disclosure due to
    manipulated URL object (bsc#1173576).

  - CVE-2020-12419: Use-after-free in nsGlobalWindowInner
    (bsc#1173576).

  - CVE-2020-12420: Use-After-Free when trying to connect to
    a STUN server (bsc#1173576).

  - CVE-2020-12402: RSA Key Generation vulnerable to
    side-channel attack (bsc#1173576).

  - CVE-2020-12421: Add-On updates did not respect the same
    certificate trust rules as software updates
    (bsc#1173576).

  - CVE-2020-12422: Integer overflow in
    nsJPEGEncoder::emptyOutputBuffer (bsc#1173576).

  - CVE-2020-12423: DLL Hijacking due to searching %PATH%
    for a library (bsc#1173576).

  - CVE-2020-12424: WebRTC permission prompt could have been
    bypassed by a compromised content process (bsc#1173576).

  - CVE-2020-12425: Out of bound read in Date.parse()
    (bsc#1173576).

  - CVE-2020-12426: Memory safety bugs fixed in Firefox 78
    (bsc#1173576).

  - FIPS: MozillaFirefox: allow
    /proc/sys/crypto/fips_enabled (bsc#1167231).

Non-security issues fixed :

  - Fixed interaction with freetype6 (bsc#1173613).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173613"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-branding-upstream-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-buildsymbols-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debuginfo-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debugsource-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-devel-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-common-78.0.1-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-other-78.0.1-lp152.2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
