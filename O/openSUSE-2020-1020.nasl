#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1020.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138787);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6515", "CVE-2020-6516", "CVE-2020-6517", "CVE-2020-6518", "CVE-2020-6519", "CVE-2020-6520", "CVE-2020-6521", "CVE-2020-6522", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6525", "CVE-2020-6526", "CVE-2020-6527", "CVE-2020-6528", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6536");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-1020)");
  script_summary(english:"Check for the openSUSE-2020-1020 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

  - Update to 84.0.4147.89 boo#1174189 :

  - Critical CVE-2020-6510: Heap buffer overflow in
    background fetch. 

  - High CVE-2020-6511: Side-channel information leakage in
    content security policy. 

  - High CVE-2020-6512: Type Confusion in V8. 

  - High CVE-2020-6513: Heap buffer overflow in PDFium. 

  - High CVE-2020-6514: Inappropriate implementation in
    WebRTC. 

  - High CVE-2020-6515: Use after free in tab strip. 

  - High CVE-2020-6516: Policy bypass in CORS. 

  - High CVE-2020-6517: Heap buffer overflow in history. 

  - Medium CVE-2020-6518: Use after free in developer tools. 

  - Medium CVE-2020-6519: Policy bypass in CSP. 

  - Medium CVE-2020-6520: Heap buffer overflow in Skia. 

  - Medium CVE-2020-6521: Side-channel information leakage
    in autofill.

  - Medium CVE-2020-6522: Inappropriate implementation in
    external protocol handlers. 

  - Medium CVE-2020-6523: Out of bounds write in Skia. 

  - Medium CVE-2020-6524: Heap buffer overflow in WebAudio. 

  - Medium CVE-2020-6525: Heap buffer overflow in Skia. 

  - Low CVE-2020-6526: Inappropriate implementation in
    iframe sandbox. 

  - Low CVE-2020-6527: Insufficient policy enforcement in
    CSP. 

  - Low CVE-2020-6528: Incorrect security UI in basic auth. 

  - Low CVE-2020-6529: Inappropriate implementation in
    WebRTC. 

  - Low CVE-2020-6530: Out of bounds memory access in
    developer tools. 

  - Low CVE-2020-6531: Side-channel information leakage in
    scroll to text. 

  - Low CVE-2020-6533: Type Confusion in V8. 

  - Low CVE-2020-6534: Heap buffer overflow in WebRTC. 

  - Low CVE-2020-6535: Insufficient data validation in
    WebUI. 

  - Low CVE-2020-6536: Incorrect security UI in PWAs.

  - Use bundled xcb-proto as we need to generate py2
    bindings

  - Try to fix non-wayland build for Leap builds"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174189"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-84.0.4147.89-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-84.0.4147.89-lp152.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-84.0.4147.89-lp152.2.6.2", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-84.0.4147.89-lp152.2.6.2", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debugsource-84.0.4147.89-lp152.2.6.2", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
