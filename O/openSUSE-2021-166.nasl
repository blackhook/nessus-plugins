#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-166.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145485);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-16044",
    "CVE-2021-21117",
    "CVE-2021-21118",
    "CVE-2021-21119",
    "CVE-2021-21120",
    "CVE-2021-21121",
    "CVE-2021-21122",
    "CVE-2021-21123",
    "CVE-2021-21124",
    "CVE-2021-21125",
    "CVE-2021-21126",
    "CVE-2021-21127",
    "CVE-2021-21128",
    "CVE-2021-21129",
    "CVE-2021-21130",
    "CVE-2021-21131",
    "CVE-2021-21132",
    "CVE-2021-21133",
    "CVE-2021-21134",
    "CVE-2021-21135",
    "CVE-2021-21136",
    "CVE-2021-21137",
    "CVE-2021-21138",
    "CVE-2021-21139",
    "CVE-2021-21140",
    "CVE-2021-21141"
  );

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2021-166)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

Chromium was updated to 88.0.4324.96 boo#1181137

  - CVE-2021-21117: Insufficient policy enforcement in
    Cryptohome

  - CVE-2021-21118: Insufficient data validation in V8

  - CVE-2021-21119: Use after free in Media

  - CVE-2021-21120: Use after free in WebSQL

  - CVE-2021-21121: Use after free in Omnibox

  - CVE-2021-21122: Use after free in Blink

  - CVE-2021-21123: Insufficient data validation in File
    System API

  - CVE-2021-21124: Potential user after free in Speech
    Recognizer

  - CVE-2021-21125: Insufficient policy enforcement in File
    System API

  - CVE-2020-16044: Use after free in WebRTC

  - CVE-2021-21126: Insufficient policy enforcement in
    extensions

  - CVE-2021-21127: Insufficient policy enforcement in
    extensions

  - CVE-2021-21128: Heap buffer overflow in Blink

  - CVE-2021-21129: Insufficient policy enforcement in File
    System API

  - CVE-2021-21130: Insufficient policy enforcement in File
    System API

  - CVE-2021-21131: Insufficient policy enforcement in File
    System API

  - CVE-2021-21132: Inappropriate implementation in DevTools

  - CVE-2021-21133: Insufficient policy enforcement in
    Downloads

  - CVE-2021-21134: Incorrect security UI in Page Info

  - CVE-2021-21135: Inappropriate implementation in
    Performance API

  - CVE-2021-21136: Insufficient policy enforcement in
    WebView

  - CVE-2021-21137: Inappropriate implementation in DevTools

  - CVE-2021-21138: Use after free in DevTools

  - CVE-2021-21139: Inappropriate implementation in iframe
    sandbox

  - CVE-2021-21140: Uninitialized Use in USB

  - CVE-2021-21141: Insufficient policy enforcement in File
    System API");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181137");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-88.0.4324.96-lp151.2.171.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-88.0.4324.96-lp151.2.171.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-88.0.4324.96-lp151.2.171.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-88.0.4324.96-lp151.2.171.1", allowmaj:TRUE) ) flag++;

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
