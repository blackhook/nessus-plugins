#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2096.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143357);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-15999",
    "CVE-2020-16012",
    "CVE-2020-26951",
    "CVE-2020-26953",
    "CVE-2020-26956",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26965",
    "CVE-2020-26966",
    "CVE-2020-26968"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-2096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaThunderbird fixes the following issues :

TODO

  - Mozilla Thunderbird 78.5.0

  - new: OpenPGP: Added option to disable attaching the
    public key to a signed message (bmo#1654950)

  - new: MailExtensions: 'compose_attachments' context added
    to Menus API (bmo#1670822)

  - new: MailExtensions: Menus API now available on
    displayed messages (bmo#1670825)

  - changed: MailExtensions: browser.tabs.create will now
    wait for 'mail-delayed-startup-finished' event
    (bmo#1674407)

  - fixed: OpenPGP: Support for inline PGP messages improved
    (bmo#1672851)

  - fixed: OpenPGP: Message security dialog showed
    unverified keys as unavailable (bmo#1675285)

  - fixed: Chat: New chat contact menu item did not function
    (bmo#1663321)

  - fixed: Various theme and usability improvements
    (bmo#1673861)

  - fixed: Various security fixes MFSA 2020-52 (bsc#1178894)

  - CVE-2020-26951 (bmo#1667113) Parsing mismatches could
    confuse and bypass security sanitizer for chrome
    privileged code

  - CVE-2020-16012 (bmo#1642028) Variable time processing of
    cross-origin images during drawImage calls

  - CVE-2020-26953 (bmo#1656741) Fullscreen could be enabled
    without displaying the security UI

  - CVE-2020-26956 (bmo#1666300) XSS through paste (manual
    and clipboard API)

  - CVE-2020-26958 (bmo#1669355) Requests intercepted
    through ServiceWorkers lacked MIME type restrictions

  - CVE-2020-26959 (bmo#1669466) Use-after-free in
    WebRequestService

  - CVE-2020-26960 (bmo#1670358) Potential use-after-free in
    uses of nsTArray

  - CVE-2020-15999 (bmo#1672223) Heap buffer overflow in
    freetype

  - CVE-2020-26961 (bmo#1672528) DoH did not filter IPv4
    mapped IP Addresses

  - CVE-2020-26965 (bmo#1661617) Software keyboards may have
    remembered typed passwords

  - CVE-2020-26966 (bmo#1663571) Single-word search queries
    were also broadcast to local network

  - CVE-2020-26968 (bmo#1551615, bmo#1607762, bmo#1656697,
    bmo#1657739, bmo#1660236, bmo#1667912, bmo#1671479,
    bmo#1671923) Memory safety bugs fixed in Thunderbird
    78.5

  - Mozilla Thunderbird 78.4.3 

  - fixed: User interface was inconsistent when switching
    from the default theme to the dark theme and back to the
    default theme (bmo#1659282)

  - fixed: Email subject would disappear when hovering over
    it with the mouse when using Windows 7 Classic theme
    (bmo#1675970)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178894");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-78.5.0-lp152.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-debuginfo-78.5.0-lp152.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-debugsource-78.5.0-lp152.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-translations-common-78.5.0-lp152.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-translations-other-78.5.0-lp152.2.19.1") ) flag++;

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
