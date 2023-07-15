#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2251.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129664);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-11710", "CVE-2019-11714", "CVE-2019-11716", "CVE-2019-11718", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11733", "CVE-2019-11735", "CVE-2019-11736", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11751", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-9811", "CVE-2019-9812");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2019-2251)");
  script_summary(english:"Check for the openSUSE-2019-2251 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox to 68.1 fixes the following issues :

Security issues fixed :

  - CVE-2019-9811: Fixed a sandbox escape via installation
    of malicious language pack. (bsc#1140868)

  - CVE-2019-9812: Fixed a sandbox escape through Firefox
    Sync. (bsc#1149294)

  - CVE-2019-11710: Fixed several memory safety bugs.
    (bsc#1140868)

  - CVE-2019-11714: Fixed a potentially exploitable crash in
    Necko. (bsc#1140868)

  - CVE-2019-11716: Fixed a sandbox bypass. (bsc#1140868)

  - CVE-2019-11718: Fixed inadequate sanitation in the
    Activity Stream component. (bsc#1140868)

  - CVE-2019-11720: Fixed a character encoding XSS
    vulnerability. (bsc#1140868)

  - CVE-2019-11721: Fixed a homograph domain spoofing issue
    through unicode latin 'kra' character. (bsc#1140868)

  - CVE-2019-11723: Fixed a cookie leakage during add-on
    fetching across private browsing boundaries.
    (bsc#1140868)

  - CVE-2019-11724: Fixed an outdated permission, granting
    access to retired site input.mozilla.org. (bsc#1140868)

  - CVE-2019-11725: Fixed a Safebrowsing bypass involving
    WebSockets. (bsc#1140868)

  - CVE-2019-11727: Fixed a vulnerability where it possible
    to force NSS to sign CertificateVerify with PKCS#1 v1.5
    signatures when those are the only ones advertised by
    server in CertificateRequest in TLS 1.3. (bsc#1141322)

  - CVE-2019-11728: Fixed an improper handling of the
    Alt-Svc header that allowed remote port scans.
    (bsc#1140868)

  - CVE-2019-11733: Fixed an insufficient protection of
    stored passwords in 'Saved Logins'. (bnc#1145665)

  - CVE-2019-11735: Fixed several memory safety bugs.
    (bnc#1149293)

  - CVE-2019-11736: Fixed a file manipulation and privilege
    escalation in Mozilla Maintenance Service. (bnc#1149292) 

  - CVE-2019-11738: Fixed a content security policy bypass
    through hash-based sources in directives. (bnc#1149302)

  - CVE-2019-11740: Fixed several memory safety bugs.
    (bsc#1149299)

  - CVE-2019-11742: Fixed a same-origin policy violation
    involving SVG filters and canvas to steal cross-origin
    images. (bsc#1149303)

  - CVE-2019-11743: Fixed a timing side-channel attack on
    cross-origin information, utilizing unload event
    attributes. (bsc#1149298)

  - CVE-2019-11744: Fixed an XSS caused by breaking out of
    title and textarea elements using innerHTML.
    (bsc#1149304)

  - CVE-2019-11746: Fixed a use-after-free while
    manipulating video. (bsc#1149297)

  - CVE-2019-11752: Fixed a use-after-free while extracting
    a key value in IndexedDB. (bsc#1149296)

  - CVE-2019-11753: Fixed a privilege escalation with
    Mozilla Maintenance Service in custom Firefox
    installation location. (bsc#1149295)

Non-security issues fixed :

&#9; - Latest update now also released for s390x. (bsc#1109465)

  - Fixed a segmentation fault on s390vsl082. (bsc#1117473)

  - Fixed a crash on SLES15 s390x. (bsc#1124525)

  - Fixed a segmentation fault. (bsc#1133810)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1138688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149323"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-branding-upstream-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-buildsymbols-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debuginfo-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debugsource-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-devel-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-common-68.1.0-lp151.2.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-other-68.1.0-lp151.2.14.1") ) flag++;

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
