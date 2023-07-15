#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2324.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145332);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26978", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-2324)");
  script_summary(english:"Check for the openSUSE-2020-2324 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird fixes the following issues :

  - Mozilla Thunderbird 78.6

  - new: MailExtensions: Added
    browser.windows.openDefaultBrowser() (bmo#1664708)

  - changed: Thunderbird now only shows quota exceeded
    indications on the main window (bmo#1671748)

  - changed: MailExtensions: menus API enabled in messages
    being composed (bmo#1670832)

  - changed: MailExtensions: Honor allowScriptsToClose
    argument in windows.create API function (bmo#1675940)

  - changed: MailExtensions: APIs that returned an accountId
    will reflect the account the message belongs to, not
    what is stored in message headers (bmo#1644032)

  - fixed: Keyboard shortcut for toggling message 'read'
    status not shown in menus (bmo#1619248)

  - fixed: OpenPGP: After importing a secret key, Key
    Manager displayed properties of the wrong key
    (bmo#1667054)

  - fixed: OpenPGP: Inline PGP parsing improvements
    (bmo#1660041)

  - fixed: OpenPGP: Discovering keys online via Key Manager
    sometimes failed on Linux (bmo#1634053)

  - fixed: OpenPGP: Encrypted attachment 'Decrypt and
    Open/Save As' did not work (bmo#1663169)

  - fixed: OpenPGP: Importing keys failed on macOS
    (bmo#1680757)

  - fixed: OpenPGP: Verification of clear signed UTF-8 text
    failed (bmo#1679756)

  - fixed: Address book: Some columns incorrectly displayed
    no data (bmo#1631201)

  - fixed: Address book: The address book view did not
    update after changing the name format in the menu
    (bmo#1678555)

  - fixed: Calendar: Could not import an ICS file into a
    CalDAV calendar (bmo#1652984)

  - fixed: Calendar: Two 'Home' calendars were visible on a
    new profile (bmo#1656782)

  - fixed: Calendar: Dark theme was incomplete on Linux
    (bmo#1655543)

  - fixed: Dark theme did not apply to new mail notification
    popups (bmo#1681083)

  - fixed: Folder icon, message list, and contact side bar
    visual improvements (bmo#1679436)

  - fixed: MailExtensions: HTTP refresh in browser content
    tabs did not work (bmo#1667774)

  - fixed: MailExtensions: messageDisplayScripts failed to
    run in main window (bmo#1674932)

  - fixed: Various security fixes MFSA 2020-56 (bsc#1180039)

  - CVE-2020-16042 (bmo#1679003) Operations on a BigInt
    could have caused uninitialized memory to be exposed

  - CVE-2020-26971 (bmo#1663466) Heap buffer overflow in
    WebGL

  - CVE-2020-26973 (bmo#1680084) CSS Sanitizer performed
    incorrect sanitization

  - CVE-2020-26974 (bmo#1681022) Incorrect cast of
    StyleGenericFlexBasis resulted in a heap use-after-free

  - CVE-2020-26978 (bmo#1677047) Internal network hosts
    could have been probed by a malicious webpage

  - CVE-2020-35111 (bmo#1657916) The proxy.onRequest API did
    not catch view-source URLs

  - CVE-2020-35112 (bmo#1661365) Opening an extension-less
    download may have inadvertently launched an executable
    instead

  - CVE-2020-35113 (bmo#1664831, bmo#1673589) Memory safety
    bugs fixed in Thunderbird 78.6

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180039"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-78.6.0-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debuginfo-78.6.0-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-debugsource-78.6.0-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-common-78.6.0-lp151.2.63.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaThunderbird-translations-other-78.6.0-lp151.2.63.1") ) flag++;

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
