#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2249.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129663);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-11709", "CVE-2019-11710", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11714", "CVE-2019-11715", "CVE-2019-11716", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-11739", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752", "CVE-2019-11755");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2019-2249)");
  script_summary(english:"Check for the openSUSE-2019-2249 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird to version 68.1.1 fixes the
following issues :

  - CVE-2019-11709: Fixed several memory safety bugs.
    (bsc#1140868)

  - CVE-2019-11710: Fixed several memory safety bugs.
    (bsc#1140868)

  - CVE-2019-11711: Fixed a script injection within domain
    through inner window reuse. (bsc#1140868)

  - CVE-2019-11712: Fixed an insufficient validation of
    cross-origin POST requests within NPAPI plugins.
    (bsc#1140868)

  - CVE-2019-11713: Fixed a use-after-free with HTTP/2
    cached stream. (bsc#1140868)

  - CVE-2019-11714: Fixed a crash in NeckoChild.
    (bsc#1140868)

  - CVE-2019-11715: Fixed an HTML parsing error that can
    contribute to content XSS. (bsc#1140868)

  - CVE-2019-11716: Fixed an enumeration issue in
    globalThis. (bsc#1140868)

  - CVE-2019-11717: Fixed an improper escaping of the caret
    character in origins. (bsc#1140868)

  - CVE-2019-11719: Fixed an out-of-bounds read when
    importing curve25519 private key. (bsc#1140868)

  - CVE-2019-11720: Fixed a character encoding XSS
    vulnerability. (bsc#1140868)

  - CVE-2019-11721: Fixed domain spoofing through unicode
    latin 'kra' character. (bsc#1140868)

  - CVE-2019-11723: Fixed a cookie leakage during add-on
    fetching across private browsing boundaries.
    (bsc#1140868)

  - CVE-2019-11724: Fixed a permissions issue with the
    retired site input.mozilla.org. (bsc#1140868)

  - CVE-2019-11725: Fixed a SafeBrowsing bypass through
    WebSockets. (bsc#1140868)

  - CVE-2019-11727: Fixed an insufficient validation for
    PKCS#1 v1.5 signatures being used with TLS 1.3.
    (bsc#1140868)

  - CVE-2019-11728: Fixed port scanning through Alt-Svc
    header. (bsc#1140868)

  - CVE-2019-11729: Fixed a segmentation fault due to empty
    or malformed p256-ECDH public keys. (bsc#1140868)

  - CVE-2019-11730: Fixed an insufficient enforcement of the
    same-origin policy that treats all files in a directory
    as having the same-origin. (bsc#1140868)

  - CVE-2019-11739: Fixed a Covert Content Attack on S/MIME
    encryption using a crafted multipart/alternative
    message. (bsc#1150939)

  - CVE-2019-11740: Fixed several memory safety bugs.
    (bsc#1149299)

  - CVE-2019-11742: Fixed a same-origin policy violation
    with SVG filters and canvas that enabled theft of
    cross-origin images. (bsc#1149303)

  - CVE-2019-11743: Fixed a cross-origin access issue.
    (bsc#1149298)

  - CVE-2019-11744: Fixed a XSS involving breaking out of
    title and textarea elements using innerHTML.
    (bsc#1149304)

  - CVE-2019-11746: Fixed a use-after-free while
    manipulating video. (bsc#1149297)

  - CVE-2019-11752: Fixed a use-after-free while extracting
    a key value in IndexedDB. (bsc#1149296)

  - CVE-2019-11755: Fixed an insufficient validation of
    S/MIME messages that allowed the author to be spoofed.
    (bsc#1152375)

This update was imported from the SUSE:SLE-15:Update update project."
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152375"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-buildsymbols-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-68.1.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"enigmail-2.1.2-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
