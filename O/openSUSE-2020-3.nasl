#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-3.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132764);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/15");

  script_cve_id("CVE-2019-11745", "CVE-2019-13722", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17009", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-3)");
  script_summary(english:"Check for the openSUSE-2020-3 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird fixes the following issues :

Mozilla Thunderbird was updated to 68.3esr (MFSA 2019-38 bsc#1158328)
&#9; 

Security issues fixed :

  - CVE-2019-17008: Fixed a use-after-free in worker
    destruction (bmo#1546331)

  - CVE-2019-13722: Fixed a stack corruption due to
    incorrect number of arguments in WebRTC code
    (bmo#1580156)

  - CVE-2019-11745: Fixed an out of bounds write in NSS when
    encrypting with a block cipher (bmo#1586176)

  - CVE-2019-17009: Fixed an issue where updater temporary
    files accessible to unprivileged processes (bmo#1510494)

  - CVE-2019-17010: Fixed a use-after-free when performing
    device orientation checks (bmo#1581084)

  - CVE-2019-17005: Fixed a buffer overflow in plain text
    serializer (bmo#1584170)

  - CVE-2019-17011: Fixed a use-after-free when retrieving a
    document in antitracking (bmo#1591334)

  - CVE-2019-17012: Fixed multiple memmory issues
    (bmo#1449736, bmo#1533957, bmo#1560667,bmo#1567209,
    bmo#1580288, bmo#1585760, bmo#1592502)

Other issues addressed :

  - New: Message display toolbar action WebExtension API
    (bmo#1531597)

  - New: Navigation buttons are now available in content
    tabs (bmo#787683)

  - Fixed an issue where write window was not always correct
    (bmo#1593280)

  - Fixed toolbar issues (bmo#1584160)

  - Fixed issues with LDAP lookup when SSL was enabled
    (bmo#1576364)

  - Fixed an issue with scam link confirmation panel
    (bmo#1596413)

  - Fixed an issue with the write window where the Link
    Properties dialog was not showing named anchors in
    context menu (bmo#1593629)

  - Fixed issues with calendar (bmo#1588516)

  - Fixed issues with chat where reordering via
    drag-and-drop was not working on Instant messaging
    status dialog (bmo#1591505)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17012");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/10");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-68.3.0-lp151.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-68.3.0-lp151.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-68.3.0-lp151.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-68.3.0-lp151.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-68.3.0-lp151.2.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-debuginfo / etc");
}
