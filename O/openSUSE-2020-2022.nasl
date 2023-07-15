#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2022.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(143295);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/03");

  script_cve_id("CVE-2020-26950");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-2020-2022)");
  script_summary(english:"Check for the openSUSE-2020-2022 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaThunderbird fixes the following issues :

  - Mozilla Thunderbird 78.4.2 MFSA 2020-49 (bsc#1178611)

  - CVE-2020-26950 (bmo#1675905) Write side effects in
    MCallGetProperty opcode not accounted for

  - Mozilla Thunderbird 78.4.1

  - new: Thunderbird prompts for an address to use when
    starting an email from an address book entry with
    multiple addresses (bmo#84028)

  - fixed: Searching global search results did not work
    (bmo#1664761)

  - fixed: Link location was not focused by default when
    adding a hyperlink in message composer (bmo#1670660)

  - fixed: Advanced address book search dialog was unusable
    (bmo#1668147)

  - fixed: Encrypted draft reply emails lost 'Re:' prefix
    (bmo#1661510)

  - fixed: Replying to a newsgroup message did not open the
    compose window (bmo#1672667)

  - fixed: Unable to delete multiple newsgroup messages
    (bmo#1657988)

  - fixed: Appmenu displayed visual glitches (bmo#1636243)

  - fixed: Visual glitches when selecting multiple messages
    in the message pane and using Ctrl+click (bmo#1671800)

  - fixed: Switching between dark and light mode could lead
    to unreadable text on macOS (bmo#1668989)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178611"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26950");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox MCallGetProperty Write Side Effects Use After Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-78.4.2-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-debuginfo-78.4.2-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-debugsource-78.4.2-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-translations-common-78.4.2-lp152.2.16.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaThunderbird-translations-other-78.4.2-lp152.2.16.1") ) flag++;

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
