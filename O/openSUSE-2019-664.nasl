#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-664.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123288);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5187", "CVE-2018-5188");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2019-664)");
  script_summary(english:"Check for the openSUSE-2019-664 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird to version 60.0 fixes the following
issues :

These security issues were fixed :

  - CVE-2018-12359: Prevent buffer overflow using computed
    size of canvas element (bsc#1098998).

  - CVE-2018-12360: Prevent use-after-free when using
    focus() (bsc#1098998).

  - CVE-2018-12361: Prevent integer overflow in SwizzleData
    (bsc#1098998).

  - CVE-2018-12362: Prevent integer overflow in SSSE3 scaler
    (bsc#1098998).

  - CVE-2018-5156: Prevent media recorder segmentation fault
    when track type is changed during capture (bsc#1098998).

  - CVE-2018-12363: Prevent use-after-free when appending
    DOM nodes (bsc#1098998).

  - CVE-2018-12364: Prevent CSRF attacks through 307
    redirects and NPAPI plugins (bsc#1098998).

  - CVE-2018-12365: Prevent compromised IPC child process
    listing local filenames (bsc#1098998).

  - CVE-2018-12371: Prevent integer overflow in Skia library
    during edge builder allocation (bsc#1098998).

  - CVE-2018-12366: Prevent invalid data handling during
    QCMS transformations (bsc#1098998).

  - CVE-2018-12367: Timing attack mitigation of
    PerformanceNavigationTiming (bsc#1098998).

  - CVE-2018-5187: Various memory safety bugs (bsc#1098998).

  - CVE-2018-5188: Various memory safety bugs (bsc#1098998).

These can not, in general, be exploited through email, but are
potential risks in browser or browser-like contexts.

These non-security issues were fixed :

  - Storing of remote content settings fixed (bsc#1084603)

  - Improved message handling and composing

  - Improved handling of message templates

  - Support for OAuth2 and FIDO U2F

  - Various Calendar improvements

  - Various fixes and changes to e-mail workflow 

  - Various IMAP fixes

  - Native desktop notifications"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-60.0-lp150.3.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-buildsymbols-60.0-lp150.3.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debuginfo-60.0-lp150.3.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-debugsource-60.0-lp150.3.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-common-60.0-lp150.3.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaThunderbird-translations-other-60.0-lp150.3.14.1") ) flag++;

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
