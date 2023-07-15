#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145306);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-15995", "CVE-2020-16043", "CVE-2021-21106", "CVE-2021-21107", "CVE-2021-21108", "CVE-2021-21109", "CVE-2021-21110", "CVE-2021-21111", "CVE-2021-21112", "CVE-2021-21113", "CVE-2021-21114", "CVE-2021-21115", "CVE-2021-21116");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2021-139)");
  script_summary(english:"Check for the openSUSE-2021-139 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

  - Update to version 73.0.3856.344

  - CHR-8265 Update chromium on desktop-stable-87-3856 to
    87.0.4280.141

  - DNA-90625 [Mac] Crash at opera::TabView::
    GetPaintData(opera::TabState) const

  - DNA-90735 Crash at
    opera::BrowserSidebarModel::GetItemVisible
    (opera::BrowserSidebarItem const*) const

  - DNA-90780 Crash at
    extensions::CommandService::GetExtension
    ActionCommand(std::__1::basic_string const&,
    extensions:: ActionInfo::Type,
    extensions::CommandService::QueryType,
    extensions::Command*, bool*)

  - DNA-90821 Crash at opera::BrowserSidebarController::
    Action(opera::BrowserSidebarItem const*,
    opera::BrowserSidebarItemContentView*)

  - The update to chromium 87.0.4280.141 fixes following
    issues: CVE-2021-21106, CVE-2021-21107, CVE-2021-21108,
    CVE-2021-21109, CVE-2021-21110, CVE-2021-21111,
    CVE-2021-21112, CVE-2021-21113, CVE-2020-16043,
    CVE-2021-21114, CVE-2020-15995, CVE-2021-21115,
    CVE-2021-21116

  - Update to version 73.0.3856.329

  - DNA-89156 Crash at
    content::RenderViewHostImpl::OnFocus()

  - DNA-89731 [Mac] Bookmarks bar overlaps Babe section when
    hovering the OMenu

  - DNA-90189 Music service portal logotypes are blurred on
    Win

  - DNA-90336 add session data schema

  - DNA-90399 Address bar dropdown suggestions overlap each
    other

  - DNA-90520 Crash at
    absl::raw_logging_internal::RawLog(absl:: LogSeverity,
    char const*, int, char const*, &hellip;)

  - DNA-90538 Crash at extensions::CommandService::
    GetExtensionActionCommand(std::__1::basic_string const&,
    extensions::ActionInfo::Type,
    extensions::CommandService:: QueryType,
    extensions::Command*, bool*)

  - DNA-90600 Don&rsquo;t report workspace visibility, when
    functionality is disabled.

  - DNA-90665 Collect music service statistics WP2

  - DNA-90773 Bad translation from english to spanish in UI

  - DNA-90789 Crash at
    opera::ThumbnailHelper::RunNextRequest()"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/22");
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

if ( rpm_check(release:"SUSE15.2", reference:"opera-73.0.3856.344-lp152.2.30.1") ) flag++;

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
