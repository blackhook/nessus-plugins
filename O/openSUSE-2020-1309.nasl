#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1309.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140171);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/30");

  script_cve_id("CVE-2020-6558", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-1309)");
  script_summary(english:"Check for the openSUSE-2020-1309 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

Chromium was updated to version 85.0.4183.83 (boo#1175757) fixing :

  - CVE-2020-6558: Insufficient policy enforcement in iOS

  - CVE-2020-6559: Use after free in presentation API

  - CVE-2020-6560: Insufficient policy enforcement in
    autofill

  - CVE-2020-6561: Inappropriate implementation in Content
    Security Policy

  - CVE-2020-6562: Insufficient policy enforcement in Blink

  - CVE-2020-6563: Insufficient policy enforcement in intent
    handling.

  - CVE-2020-6564: Incorrect security UI in permissions

  - CVE-2020-6565: Incorrect security UI in Omnibox.

  - CVE-2020-6566: Insufficient policy enforcement in media. 

  - CVE-2020-6567: Insufficient validation of untrusted
    input in command line handling.

  - CVE-2020-6568: Insufficient policy enforcement in intent
    handling.

  - CVE-2020-6569: Integer overflow in WebUSB.

  - CVE-2020-6570: Side-channel information leakage in
    WebRTC. 

  - CVE-2020-6571: Incorrect security UI in Omnibox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175757"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6559");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");
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

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-85.0.4183.69-lp151.2.123.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-85.0.4183.69-lp151.2.123.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-85.0.4183.69-lp151.2.123.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-85.0.4183.69-lp151.2.123.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-85.0.4183.69-lp151.2.123.1", allowmaj:TRUE) ) flag++;

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
