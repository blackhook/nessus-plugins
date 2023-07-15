#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-296.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146501);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-21148");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0007");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2021-296)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for opera fixes the following issues :

  - Update to version 74.0.3911.107

  - CHR-8311 Update chromium on desktop-stable-88-3911 to
    88.0.4324.150

  - DNA-90329 Implement client_capabilities negotiation for
    Flow / Sync

  - DNA-90560 [Search Tabs] Open Tabs On Top

  - DNA-90620 Add opauto tests for tab snoozing

  - DNA-90628 Update opauto tests after design changes

  - DNA-90818 Only 3 recently closed tabs are shown in a
    search mode

  - DNA-90911 Enable search-tabs-open-tabs-on-top on
    developer

  - DNA-90990 Crash at
    opera::AddressBarView::NotifyBoundsChanged()

  - DNA-90991 Opera doesn&rsquo;t show version and
    &lsquo;Relaunch&rsquo; button despite update is ready

  - DNA-91097 Crash at
    extensions::BrowserSidebarPrivateGetPremium
    ExtensionsInfoFunction::Run()

  - DNA-91163 [Win] &ldquo;URL navigation filters&rdquo;
    subpage doesn&rsquo;t react on actions

  - DNA-91196 [Flow] Device capabilities is not properly
    saved in Local State

  - DNA-91276 Sidebar setup wont open

  - The update to chromium 88.0.4324.150 fixes following
    issues :

  - CVE-2021-21148 (1181827)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181827");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

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

if ( rpm_check(release:"SUSE15.2", reference:"opera-74.0.3911.107-lp152.2.34.1") ) flag++;

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
