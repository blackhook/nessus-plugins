#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-712.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123310);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2018-17462",
    "CVE-2018-17463",
    "CVE-2018-17464",
    "CVE-2018-17465",
    "CVE-2018-17466",
    "CVE-2018-17467",
    "CVE-2018-17468",
    "CVE-2018-17469",
    "CVE-2018-17470",
    "CVE-2018-17471",
    "CVE-2018-17472",
    "CVE-2018-17473",
    "CVE-2018-17474",
    "CVE-2018-17475",
    "CVE-2018-17476",
    "CVE-2018-17477",
    "CVE-2018-5179"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2019-712)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for Chromium to version 70.0.3538.67 fixes multiple
issues.

Security issues fixed (bsc#1112111) :

  - CVE-2018-17462: Sandbox escape in AppCache

  - CVE-2018-17463: Remote code execution in V8

  - Heap buffer overflow in Little CMS in PDFium

  - CVE-2018-17464: URL spoof in Omnibox

  - CVE-2018-17465: Use after free in V8

  - CVE-2018-17466: Memory corruption in Angle

  - CVE-2018-17467: URL spoof in Omnibox

  - CVE-2018-17468: Cross-origin URL disclosure in Blink

  - CVE-2018-17469: Heap buffer overflow in PDFium

  - CVE-2018-17470: Memory corruption in GPU Internals

  - CVE-2018-17471: Security UI occlusion in full screen
    mode

  - CVE-2018-17473: URL spoof in Omnibox

  - CVE-2018-17474: Use after free in Blink

  - CVE-2018-17475: URL spoof in Omnibox

  - CVE-2018-17476: Security UI occlusion in full screen
    mode

  - CVE-2018-5179: Lack of limits on update() in
    ServiceWorker

  - CVE-2018-17477: UI spoof in Extensions VAAPI hardware
    accelerated rendering is now enabled by default.

This update contains the following packaging changes :

  - Use the system libusb-1.0 library

  - Use bundled harfbuzz library

  - Disable gnome-keyring to avoid crashes");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112111");
  script_set_attribute(attribute:"solution", value:
"Update the affected Chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17474");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 67, 68 and 69 Object.create exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-70.0.3538.67-lp150.2.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromedriver-debuginfo-70.0.3538.67-lp150.2.20.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-70.0.3538.67-lp150.2.20.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debuginfo-70.0.3538.67-lp150.2.20.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"chromium-debugsource-70.0.3538.67-lp150.2.20.1", allowmaj:TRUE) ) flag++;

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
