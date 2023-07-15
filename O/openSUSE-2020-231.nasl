#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-231.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6800");
  script_xref(name:"IAVA", value:"2020-A-0072-S");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-231)");
  script_summary(english:"Check for the openSUSE-2020-231 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaThunderbird fixes the following issues :

  - Mozilla Thunderbird 68.5 (bsc#1162777) MFSA 2020-07
    (bsc#1163368)

  - CVE-2020-6793 (bmo#1608539) Out-of-bounds read when
    processing certain email messages

  - CVE-2020-6794 (bmo#1606619) Setting a master password
    post-Thunderbird 52 does not delete unencrypted
    previously stored passwords

  - CVE-2020-6795 (bmo#1611105) Crash processing S/MIME
    messages with multiple signatures

  - CVE-2020-6797 (bmo#1596668) Extensions granted
    downloads.open permission could open arbitrary
    applications on Mac OSX

  - CVE-2020-6798 (bmo#1602944) Incorrect parsing of
    template tag could result in JavaScript injection

  - CVE-2020-6792 (bmo#1609607) Message ID calculcation was
    based on uninitialized data

  - CVE-2020-6800 (bmo#1595786, bmo#1596706, bmo#1598543,
    bmo#1604851, bmo#1605777, bmo#1608580, bmo#1608785)
    Memory safety bugs fixed in Thunderbird 68.5

  - new: Support for Client Identity IMAP/SMTP Service
    Extension (bmo#1532388)

  - new: Support for OAuth 2.0 authentication for POP3
    accounts (bmo#1538409)

  - fixed: Status area goes blank during account setup
    (bmo#1593122)

  - fixed: Calendar: Could not remove color for default
    categories (bmo#1584853)

  - fixed: Calendar: Prevent calendar component loading
    multiple times (bmo#1606375)

  - fixed: Calendar: Today pane did not retain width between
    sessions (bmo#1610207)

  - unresolved: When upgrading from Thunderbird version 60
    to version 68, add-ons are not automatically updated
    during the upgrade process. They will however be updated
    during the add- on update check. It is of course
    possible to reinstall compatible add-ons via the Add-ons
    Manager or via addons.thunderbird.net. (bmo#1574183)

  - changed: Calendar: Task and Event tree colours adjusted
    for the dark theme (bmo#1608344)

  - fixed: Retrieval of S/MIME certificates from LDAP failed
    (bmo#1604773)

  - fixed: Address-parsing crash on some IMAP servers when
    preference mail.imap.use_envelope_cmd was set
    (bmo#1609690)

  - fixed: Incorrect forwarding of HTML messages caused SMTP
    servers to respond with a timeout (bmo#1222046)

  - fixed: Calendar: Various parts of the calendar UI
    stopped working when a second Thunderbird window opened
    (bmo#1608407)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-68.5.0-lp151.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-68.5.0-lp151.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-68.5.0-lp151.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-68.5.0-lp151.2.25.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-68.5.0-lp151.2.25.1") ) flag++;

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
