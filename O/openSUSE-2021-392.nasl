#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-392.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(147606);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-27844",
    "CVE-2021-21149",
    "CVE-2021-21150",
    "CVE-2021-21151",
    "CVE-2021-21152",
    "CVE-2021-21153",
    "CVE-2021-21154",
    "CVE-2021-21155",
    "CVE-2021-21156",
    "CVE-2021-21157",
    "CVE-2021-21159",
    "CVE-2021-21160",
    "CVE-2021-21161",
    "CVE-2021-21162",
    "CVE-2021-21163",
    "CVE-2021-21164",
    "CVE-2021-21165",
    "CVE-2021-21166",
    "CVE-2021-21167",
    "CVE-2021-21168",
    "CVE-2021-21169",
    "CVE-2021-21170",
    "CVE-2021-21171",
    "CVE-2021-21172",
    "CVE-2021-21173",
    "CVE-2021-21174",
    "CVE-2021-21175",
    "CVE-2021-21176",
    "CVE-2021-21177",
    "CVE-2021-21178",
    "CVE-2021-21179",
    "CVE-2021-21180",
    "CVE-2021-21181",
    "CVE-2021-21182",
    "CVE-2021-21183",
    "CVE-2021-21184",
    "CVE-2021-21185",
    "CVE-2021-21186",
    "CVE-2021-21187",
    "CVE-2021-21188",
    "CVE-2021-21189",
    "CVE-2021-21190"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2021-392)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

Update to 89.0.4389.72 (boo#1182358, boo#1182960) :

  - CVE-2021-21159: Heap buffer overflow in TabStrip.

  - CVE-2021-21160: Heap buffer overflow in WebAudio.

  - CVE-2021-21161: Heap buffer overflow in TabStrip.

  - CVE-2021-21162: Use after free in WebRTC.

  - CVE-2021-21163: Insufficient data validation in Reader
    Mode.

  - CVE-2021-21164: Insufficient data validation in Chrome
    for iOS.

  - CVE-2021-21165: Object lifecycle issue in audio.

  - CVE-2021-21166: Object lifecycle issue in audio.

  - CVE-2021-21167: Use after free in bookmarks.

  - CVE-2021-21168: Insufficient policy enforcement in
    appcache.

  - CVE-2021-21169: Out of bounds memory access in V8.

  - CVE-2021-21170: Incorrect security UI in Loader.

  - CVE-2021-21171: Incorrect security UI in TabStrip and
    Navigation.

  - CVE-2021-21172: Insufficient policy enforcement in File
    System API.

  - CVE-2021-21173: Side-channel information leakage in
    Network Internals.

  - CVE-2021-21174: Inappropriate implementation in
    Referrer.

  - CVE-2021-21175: Inappropriate implementation in Site
    isolation.

  - CVE-2021-21176: Inappropriate implementation in full
    screen mode.

  - CVE-2021-21177: Insufficient policy enforcement in
    Autofill.

  - CVE-2021-21178: Inappropriate implementation in
    Compositing.

  - CVE-2021-21179: Use after free in Network Internals.

  - CVE-2021-21180: Use after free in tab search.

  - CVE-2020-27844: Heap buffer overflow in OpenJPEG.

  - CVE-2021-21181: Side-channel information leakage in
    autofill.

  - CVE-2021-21182: Insufficient policy enforcement in
    navigations.

  - CVE-2021-21183: Inappropriate implementation in
    performance APIs.

  - CVE-2021-21184: Inappropriate implementation in
    performance APIs.

  - CVE-2021-21185: Insufficient policy enforcement in
    extensions.

  - CVE-2021-21186: Insufficient policy enforcement in QR
    scanning.

  - CVE-2021-21187: Insufficient data validation in URL
    formatting.

  - CVE-2021-21188: Use after free in Blink.

  - CVE-2021-21189: Insufficient policy enforcement in
    payments.

  - CVE-2021-21190: Uninitialized Use in PDFium.

  - CVE-2021-21149: Stack overflow in Data Transfer.

  - CVE-2021-21150: Use after free in Downloads.

  - CVE-2021-21151: Use after free in Payments.

  - CVE-2021-21152: Heap buffer overflow in Media.

  - CVE-2021-21153: Stack overflow in GPU Process. 

  - CVE-2021-21154: Heap buffer overflow in Tab Strip.

  - CVE-2021-21155: Heap buffer overflow in Tab Strip.

  - CVE-2021-21156: Heap buffer overflow in V8.

  - CVE-2021-21157: Use after free in Web Sockets. 

  - Fixed Sandbox with glibc 2.33 (boo#1182233)

  - Fixed an issue where chromium hangs on opening
    (boo#1182775).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182775");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27844");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-89.0.4389.72-lp152.2.77.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-89.0.4389.72-lp152.2.77.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-89.0.4389.72-lp152.2.77.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-89.0.4389.72-lp152.2.77.1", allowmaj:TRUE) ) flag++;

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
