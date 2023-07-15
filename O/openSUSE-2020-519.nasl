#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-519.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135577);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6450", "CVE-2020-6451", "CVE-2020-6452", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-519)");
  script_summary(english:"Check for the openSUSE-2020-519 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

Chromium was updated to 81.0.4044.92 boo#1168911 :

  - CVE-2020-6454: Use after free in extensions

  - CVE-2020-6423: Use after free in audio

  - CVE-2020-6455: Out of bounds read in WebSQL

  - CVE-2020-6430: Type Confusion in V8

  - CVE-2020-6456: Insufficient validation of untrusted
    input in clipboard

  - CVE-2020-6431: Insufficient policy enforcement in full
    screen

  - CVE-2020-6432: Insufficient policy enforcement in
    navigations

  - CVE-2020-6433: Insufficient policy enforcement in
    extensions

  - CVE-2020-6434: Use after free in devtools

  - CVE-2020-6435: Insufficient policy enforcement in
    extensions

  - CVE-2020-6436: Use after free in window management

  - CVE-2020-6437: Inappropriate implementation in WebView

  - CVE-2020-6438: Insufficient policy enforcement in
    extensions

  - CVE-2020-6439: Insufficient policy enforcement in
    navigations

  - CVE-2020-6440: Inappropriate implementation in
    extensions

  - CVE-2020-6441: Insufficient policy enforcement in
    omnibox

  - CVE-2020-6442: Inappropriate implementation in cache

  - CVE-2020-6443: Insufficient data validation in developer
    tools

  - CVE-2020-6444: Uninitialized Use in WebRTC

  - CVE-2020-6445: Insufficient policy enforcement in
    trusted types

  - CVE-2020-6446: Insufficient policy enforcement in
    trusted types

  - CVE-2020-6447: Inappropriate implementation in developer
    tools

  - CVE-2020-6448: Use after free in V8

Chromium was updated to 80.0.3987.162 boo#1168421 :

  - CVE-2020-6450: Use after free in WebAudio.

  - CVE-2020-6451: Use after free in WebAudio.

  - CVE-2020-6452: Heap buffer overflow in media.

  - Use a symbolic icon for GNOME"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168911"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");
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

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-81.0.4044.92-lp151.2.77.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-81.0.4044.92-lp151.2.77.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-81.0.4044.92-lp151.2.77.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-81.0.4044.92-lp151.2.77.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-81.0.4044.92-lp151.2.77.1", allowmaj:TRUE) ) flag++;

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
