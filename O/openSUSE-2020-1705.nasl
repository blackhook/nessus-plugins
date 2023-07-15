#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1705.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141840);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id("CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-6557");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-1705)");
  script_summary(english:"Check for the openSUSE-2020-1705 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

-chromium was updated to 86.0.4240.75 (boo#1177408) :

  - CVE-2020-15967: Fixed Use after free in payments.

  - CVE-2020-15968: Fixed Use after free in Blink.

  - CVE-2020-15969: Fixed Use after free in WebRTC. 

  - CVE-2020-15970: Fixed Use after free in NFC.

  - CVE-2020-15971: Fixed Use after free in printing. 

  - CVE-2020-15972: Fixed Use after free in audio. 

  - CVE-2020-15990: Fixed Use after free in autofill. 

  - CVE-2020-15991: Fixed Use after free in password
    manager.

  - CVE-2020-15973: Fixed Insufficient policy enforcement in
    extensions.

  - CVE-2020-15974: Fixed Integer overflow in Blink. 

  - CVE-2020-15975: Fixed Integer overflow in SwiftShader. 

  - CVE-2020-15976: Fixed Use after free in WebXR. 

  - CVE-2020-6557: Fixed Inappropriate implementation in
    networking. 

  - CVE-2020-15977: Fixed Insufficient data validation in
    dialogs.

  - CVE-2020-15978: Fixed Insufficient data validation in
    navigation.

  - CVE-2020-15979: Fixed Inappropriate implementation in
    V8.

  - CVE-2020-15980: Fixed Insufficient policy enforcement in
    Intents.

  - CVE-2020-15981: Fixed Out of bounds read in audio. 

  - CVE-2020-15982: Fixed Side-channel information leakage
    in cache. 

  - CVE-2020-15983: Fixed Insufficient data validation in
    webUI.

  - CVE-2020-15984: Fixed Insufficient policy enforcement in
    Omnibox. 

  - CVE-2020-15985: Fixed Inappropriate implementation in
    Blink. 

  - CVE-2020-15986: Fixed Integer overflow in media. 

  - CVE-2020-15987: Fixed Use after free in WebRTC. 

  - CVE-2020-15992: Fixed Insufficient policy enforcement in
    networking. 

  - CVE-2020-15988: Fixed Insufficient policy enforcement in
    downloads.

  - CVE-2020-15989: Fixed Uninitialized Use in PDFium."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177408"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15992");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-86.0.4240.75-lp151.2.144.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-86.0.4240.75-lp151.2.144.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-86.0.4240.75-lp151.2.144.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-86.0.4240.75-lp151.2.144.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gn-0.1807-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gn-debuginfo-0.1807-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gn-debugsource-0.1807-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-86.0.4240.75-lp152.2.39.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-86.0.4240.75-lp152.2.39.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-86.0.4240.75-lp152.2.39.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-86.0.4240.75-lp152.2.39.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gn-0.1807-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gn-debuginfo-0.1807-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gn-debugsource-0.1807-lp152.2.3.1") ) flag++;

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
