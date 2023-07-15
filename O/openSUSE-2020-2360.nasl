#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2360.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145375);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2020-16037", "CVE-2020-16038", "CVE-2020-16039", "CVE-2020-16040", "CVE-2020-16041", "CVE-2020-16042");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-2360)");
  script_summary(english:"Check for the openSUSE-2020-2360 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

  - Update to version 73.0.3856.284

  - CHR-8225 Update chromium on desktop-stable-87-3856 to
    87.0.4280.88

  - DNA-88454 Background of snap area above visible scrolled
    viewport is not captured

  - DNA-89749 Implement client_capabilities support for Flow
    / Sync

  - DNA-89810 Opera no longer autoselects full url/address
    bar when clicked

  - DNA-89923 [Snap] Emojis look grayed out

  - DNA-90060 Make gesture events work with search-in-tabs
    feature

  - DNA-90168 Display SD suggestions titles

  - DNA-90176 Player doesn&rsquo;t show music service to
    choose on Welcome page

  - DNA-90343 [Mac] Cmd+C doesn&rsquo;t copy snapshot

  - DNA-90538 Crash at extensions::CommandService::
    GetExtensionActionCommand(std::__1::basic_string const&,
    extensions::ActionInfo::Type,
    extensions::CommandService:: QueryType,
    extensions::Command*, bool*)

  - The update to chromium 87.0.4280.88 fixes following
    issues: CVE-2020-16037, CVE-2020-16038, CVE-2020-16039,
    CVE-2020-16040, CVE-2020-16041, CVE-2020-16042

  - Update to version 73.0.3856.257

  - DNA-89918 #enable-force-dark flag doesn&rsquo;t work
    anymore

  - DNA-90061 Clicking on video&rsquo;s progress bar breaks
    autopausing

  - DNA-90079 [BigSur] Blank pages

  - DNA-90154 Crash at extensions::CommandService::
    GetExtensionActionCommand(std::__1::basic_string const&,
    extensions::ActionInfo::Type,
    extensions::CommandService:: QueryType,
    extensions::Command*, bool*)

  - Complete Opera 73.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-73/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.opera.com/desktop/changelog-for-73/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 87.0.4280.88 integer overflow during SimplfiedLowering phase');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/29");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opera-73.0.3856.284-lp152.2.27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
