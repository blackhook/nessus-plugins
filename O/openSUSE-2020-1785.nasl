#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1785.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142196);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id("CVE-2020-15673", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678", "CVE-2020-15683", "CVE-2020-15969");

  script_name(english:"openSUSE Security Update : MozillaThunderbird and mozilla-nspr (openSUSE-2020-1785)");
  script_summary(english:"Check for the openSUSE-2020-1785 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird and mozilla-nspr fixes the
following issues :

  - Mozilla Thunderbird 78.4

  - new: MailExtensions: browser.tabs.sendMessage API added

  - new: MailExtensions: messageDisplayScripts API added

  - changed: Yahoo and AOL mail users using password
    authentication will be migrated to OAuth2

  - changed: MailExtensions: messageDisplay APIs extended to
    support multiple selected messages

  - changed: MailExtensions: compose.begin functions now
    support creating a message with attachments

  - fixed: Thunderbird could freeze when updating global
    search index

  - fixed: Multiple issues with handling of self-signed SSL
    certificates addressed

  - fixed: Recipient address fields in compose window could
    expand to fill all available space

  - fixed: Inserting emoji characters in message compose
    window caused unexpected behavior

  - fixed: Button to restore default folder icon color was
    not keyboard accessible

  - fixed: Various keyboard navigation fixes

  - fixed: Various color-related theme fixes

  - fixed: MailExtensions: Updating attachments with
    onBeforeSend.addListener() did not work MFSA 2020-47
    (bsc#1177977)

  - CVE-2020-15969 Use-after-free in usersctp

  - CVE-2020-15683 Memory safety bugs fixed in Thunderbird
    78.4

  - Mozilla Thunderbird 78.3.3

  - OpenPGP: Improved support for encrypting with subkeys

  - OpenPGP message status icons were not visible in message
    header pane

  - Creating a new calendar event did not require an event
    title

  - Mozilla Thunderbird 78.3.2 (bsc#1176899)

  - OpenPGP: Improved support for encrypting with subkeys

  - OpenPGP: Encrypted messages with international
    characters were sometimes displayed incorrectly

  - Single-click deletion of recipient pills with middle
    mouse button restored

  - Searching an address book list did not display results

  - Dark mode, high contrast, and Windows theming fixes

  - Mozilla Thunderbird 78.3.1

  - fix crash in nsImapProtocol::CreateNewLineFromSocket

  - Mozilla Thunderbird 78.3.0 MFSA 2020-44 (bsc#1176756)

  - CVE-2020-15677 Download origin spoofing via redirect

  - CVE-2020-15676 XSS when pasting attacker-controlled data
    into a contenteditable element

  - CVE-2020-15678 When recursing through layers while
    scrolling, an iterator may have become invalid,
    resulting in a potential use-after- free scenario

  - CVE-2020-15673 Memory safety bugs fixed in Thunderbird
    78.3

  - update mozilla-nspr to version 4.25.1

  - The macOS platform code for shared library loading was
    changed to support macOS 11.

  - Dependency needed for the MozillaThunderbird udpate

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177977"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaThunderbird and mozilla-nspr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15683");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-4.25.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-debuginfo-4.25.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-debugsource-4.25.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-devel-4.25.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaThunderbird-78.4.0-lp151.2.53.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaThunderbird-debuginfo-78.4.0-lp151.2.53.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaThunderbird-debugsource-78.4.0-lp151.2.53.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-common-78.4.0-lp151.2.53.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"MozillaThunderbird-translations-other-78.4.0-lp151.2.53.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.25.1-lp151.2.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-debuginfo-4.25.1-lp151.2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-debuginfo / etc");
}
