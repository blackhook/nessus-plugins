#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1521.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119549);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2018-17480",
    "CVE-2018-17481",
    "CVE-2018-18335",
    "CVE-2018-18336",
    "CVE-2018-18337",
    "CVE-2018-18338",
    "CVE-2018-18339",
    "CVE-2018-18340",
    "CVE-2018-18341",
    "CVE-2018-18342",
    "CVE-2018-18343",
    "CVE-2018-18344",
    "CVE-2018-18345",
    "CVE-2018-18346",
    "CVE-2018-18347",
    "CVE-2018-18348",
    "CVE-2018-18349",
    "CVE-2018-18350",
    "CVE-2018-18351",
    "CVE-2018-18352",
    "CVE-2018-18353",
    "CVE-2018-18354",
    "CVE-2018-18355",
    "CVE-2018-18356",
    "CVE-2018-18357",
    "CVE-2018-18358",
    "CVE-2018-18359"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2018-1521)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update to Chromium version 71.0.3578.80 fixes security issues and
bugs.

Security issues fixed (boo#1118529) :

  - CVE-2018-17480: Out of bounds write in V8

  - CVE-2018-17481: Use after frees in PDFium

  - CVE-2018-18335: Heap buffer overflow in Skia

  - CVE-2018-18336: Use after free in PDFium

  - CVE-2018-18337: Use after free in Blink

  - CVE-2018-18338: Heap buffer overflow in Canvas

  - CVE-2018-18339: Use after free in WebAudio

  - CVE-2018-18340: Use after free in MediaRecorder

  - CVE-2018-18341: Heap buffer overflow in Blink

  - CVE-2018-18342: Out of bounds write in V8

  - CVE-2018-18343: Use after free in Skia

  - CVE-2018-18344: Inappropriate implementation in
    Extensions

  - Multiple issues in SQLite via WebSQL

  - CVE-2018-18345: Inappropriate implementation in Site
    Isolation

  - CVE-2018-18346: Incorrect security UI in Blink

  - CVE-2018-18347: Inappropriate implementation in
    Navigation

  - CVE-2018-18348: Inappropriate implementation in Omnibox

  - CVE-2018-18349: Insufficient policy enforcement in Blink

  - CVE-2018-18350: Insufficient policy enforcement in Blink

  - CVE-2018-18351: Insufficient policy enforcement in
    Navigation

  - CVE-2018-18352: Inappropriate implementation in Media

  - CVE-2018-18353: Inappropriate implementation in Network
    Authentication

  - CVE-2018-18354: Insufficient data validation in Shell
    Integration

  - CVE-2018-18355: Insufficient policy enforcement in URL
    Formatter

  - CVE-2018-18356: Use after free in Skia

  - CVE-2018-18357: Insufficient policy enforcement in URL
    Formatter

  - CVE-2018-18358: Insufficient policy enforcement in Proxy

  - CVE-2018-18359: Out of bounds read in V8

  - Inappropriate implementation in PDFium

  - Use after free in Extensions

  - Inappropriate implementation in Navigation

  - Insufficient policy enforcement in Navigation

  - Insufficient policy enforcement in URL Formatter

  - Various fixes from internal audits, fuzzing and other
    initiatives

The following changes are included :

  - advertisements posing as error messages are now blocked

  - Automatic playing of content at page load mostly
    disabled

  - New JavaScript API for relative time display");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118529");
  script_set_attribute(attribute:"solution", value:
"Update the affected Chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-71.0.3578.80-lp150.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-71.0.3578.80-lp150.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-71.0.3578.80-lp150.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-71.0.3578.80-lp150.2.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-71.0.3578.80-lp150.2.30.1") ) flag++;

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
