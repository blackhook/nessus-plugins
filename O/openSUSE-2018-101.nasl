#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-101.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106430);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5089", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2018-101)");
  script_summary(english:"Check for the openSUSE-2018-101 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird to version 52.6 fixes several
issues.

These security issues were fixed :

  - CVE-2018-5095: Integer overflow in Skia library during
    edge builder allocation (bsc#1077291).

  - CVE-2018-5096: Use-after-free while editing form
    elements (bsc#1077291).

  - CVE-2018-5097: Use-after-free when source document is
    manipulated during XSLT (bsc#1077291).

  - CVE-2018-5098: Use-after-free while manipulating form
    input elements (bsc#1077291).

  - CVE-2018-5099: Use-after-free with widget listener
    (bsc#1077291).

  - CVE-2018-5102: Use-after-free in HTML media elements
    (bsc#1077291).

  - CVE-2018-5103: Use-after-free during mouse event
    handling (bsc#1077291).

  - CVE-2018-5104: Use-after-free during font face
    manipulation (bsc#1077291).

  - CVE-2018-5117: URL spoofing with right-to-left text
    aligned left-to-right (bsc#1077291).

  - CVE-2018-5089: Various memory safety bugs (bsc#1077291).

These security issues were fixed :

  - Searching message bodies of messages in local folders,
    including filter and quick filter operations, not
    working reliably: Content not found in base64-encode
    message parts, non-ASCII text not found and false
    positives found.

  - Defective messages (without at least one expected
    header) not shown in IMAP folders but shown on mobile
    devices

  - Calendar: Unintended task deletion if numlock is enabled"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077291"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-buildsymbols-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debuginfo-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-debugsource-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-devel-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-common-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"MozillaThunderbird-translations-other-52.6-56.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-buildsymbols-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-devel-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-52.6-56.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-52.6-56.2") ) flag++;

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
