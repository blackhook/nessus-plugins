#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-85.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106324);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5089", "CVE-2018-5091", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2018-85)");
  script_summary(english:"Check for the openSUSE-2018-85 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox fixes the following issues :

  - update to Firefox 52.6esr (boo#1077291) MFSA 2018-01

  - Speculative execution side-channel attack ('Spectre')
    MFSA 2018-03

  - CVE-2018-5091 (bmo#1423086) Use-after-free with DTMF
    timers

  - CVE-2018-5095 (bmo#1418447) Integer overflow in Skia
    library during edge builder allocation

  - CVE-2018-5096 (bmo#1418922) Use-after-free while editing
    form elements

  - CVE-2018-5097 (bmo#1387427) Use-after-free when source
    document is manipulated during XSLT

  - CVE-2018-5098 (bmo#1399400) Use-after-free while
    manipulating form input elements

  - CVE-2018-5099 (bmo#1416878) Use-after-free with widget
    listener

  - CVE-2018-5102 (bmo#1419363) Use-after-free in HTML media
    elements

  - CVE-2018-5103 (bmo#1423159) Use-after-free during mouse
    event handling

  - CVE-2018-5104 (bmo#1425000) Use-after-free during font
    face manipulation

  - CVE-2018-5117 (bmo#1395508) URL spoofing with
    right-to-left text aligned left-to-right

  - CVE-2018-5089 Memory safety bugs fixed in Firefox 58 and
    Firefox ESR 52.6

  - Added additional patches and configurations to fix
    builds on s390 and PowerPC.

  - Added firefox-glibc-getrandom.patch effecting builds on
    s390 and PowerPC

  - Added mozilla-s390-bigendian.patch along with
    icudt58b.dat bigendian ICU data file for running Firefox
    on bigendian architectures (bmo#1322212 and bmo#1264836)

  - Added mozilla-s390-nojit.patch to enable atomic
    operations used by the JS engine when JIT is disabled on
    s390

  - Build configuration options specific to s390

  - Requires NSS >= 3.29.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.6-57.30.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-branding-upstream-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-buildsymbols-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debuginfo-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-debugsource-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-devel-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-common-52.6-75.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaFirefox-translations-other-52.6-75.1") ) flag++;

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
