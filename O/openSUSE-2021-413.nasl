#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-413.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(148839);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21148",
    "CVE-2021-21149",
    "CVE-2021-21150",
    "CVE-2021-21151",
    "CVE-2021-21152",
    "CVE-2021-21153",
    "CVE-2021-21154",
    "CVE-2021-21155",
    "CVE-2021-21156",
    "CVE-2021-21157"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0007");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2021-413)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for opera fixes the following issues :

  - Update to version 74.0.3911.203

  - CHR-8324 Update chromium on desktop-stable-88-3911 to
    88.0.4324.182(boo#1182358)

  - DNA-90762 Replace &ldquo;Don&rsquo;t show again&rdquo;
    with &ldquo;Discard&rdquo;

  - DNA-90974 Crash at
    opera::PersistentRecentlyClosedWindows::GetEntryType(Ses
    sionID)

  - DNA-91289 [Search tabs] Wrong tab stays highlighted
    after removing another tab

  - DNA-91476 Invalid memory dereference
    PlayerServiceBrowsertest

  - DNA-91502 Change system name on opera://about page for
    MacOS

  - DNA-91740 Missing title in Extensions Toolbar Menu

  - The update to chromium 88.0.4324.182 fixes following
    issues: CVE-2021-21149, CVE-2021-21150, CVE-2021-21151,
    CVE-2021-21152, CVE-2021-21153, CVE-2021-21154,
    CVE-2021-21155, CVE-2021-21156, CVE-2021-21157

  - Update to version 74.0.3911.160

  - DNA-90409 Cleanup JavaScript dialogs: app modal & tab
    modal

  - DNA-90720 [Search Tabs] Allow discarding recently closed
    items

  - DNA-90802 [Windows] Debug fails on linking

  - DNA-91130 heap-use-after-free in
    CashbackBackendServiceTest.AutoUpdateSchedule

  - DNA-91152 Allow reading agent variables in trigger
    conditions

  - DNA-91225 [Search tabs] The webpage doesn&rsquo;t move
    from &ldquo;Open tabs&rdquo; to &ldquo;Recently
    closed&rdquo; section

  - DNA-91243 Add Rich Hint support for the cashback badge
    and popup

  - DNA-91483 component_unittests are timing out

  - DNA-91516 Sidebar setup opens only with cashback enabled

  - DNA-91601 No text in 1st line of address bar dropdown
    suggestions

  - DNA-91603 Jumbo build problem on desktop-stable-88-3911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182358");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21157");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21155");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"opera-74.0.3911.203-lp152.2.37.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
