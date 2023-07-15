#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1324.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-6532", "CVE-2020-6537", "CVE-2020-6538", "CVE-2020-6539", "CVE-2020-6540", "CVE-2020-6541", "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6546", "CVE-2020-6547", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6552", "CVE-2020-6553", "CVE-2020-6554", "CVE-2020-6555");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2020-1324)");
  script_summary(english:"Check for the openSUSE-2020-1324 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opera fixes the following issues :

Update to version 70.0.3728.133

  - CHR-8053 Update chromium on desktop-stable-84-3728 to
    84.0.4147.125

  - DNA-87289 Crash at views::NativeWidgetMacNSWindowHost::
    OnNativeViewHostDetach(views::View const*)

  - DNA-87831 [Linux] Sidebar panel cannot be pinned

  - DNA-88057 [Win] Black rectangle flickers at the bottom
    of the page on startup

  - DNA-88157 Sidebar Messenger too low in FullScreen mode

  - DNA-88238 [macOS 10.15] Toolbar buttons not visible on
    inactive tab

  - The update to chromium 84.0.4147.125 fixes following
    issues :

  - CVE-2020-6542, CVE-2020-6543, CVE-2020-6544,
    CVE-2020-6545, CVE-2020-6546, CVE-2020-6547,
    CVE-2020-6548, CVE-2020-6549, CVE-2020-6550,
    CVE-2020-6551, CVE-2020-6552, CVE-2020-6553,
    CVE-2020-6554, CVE-2020-6555

  - Update to version 70.0.3728.119

  - DNA-88215 Introduce easy-setup-hint-ref feature flag

  - Update to version 70.0.3728.106

  - DNA-88014 [Mac] Toolbar in fullscreen disabled after
    using fullscreen from videoplayer

  - Update to version 70.0.3728.95

  - CHR-8026 Update chromium on desktop-stable-84-3728 to
    84.0.4147.105

  - DNA-86340 Wrong link to the help page

  - DNA-87394 [Big Sur] Some popovers have incorrectly
    themed arrow

  - DNA-87647 [Win] The [+] button flickers after creating a
    new tab

  - DNA-87794 Crash at aura::Window::SetVisible(bool)

  - DNA-87796 Search in tabs should closed on second click

  - DNA-87863 Parameter placing issue in all languages

  - The update to chromium 84.0.4147.105 fixes following
    issues :

  - CVE-2020-6537, CVE-2020-6538, CVE-2020-6532,
    CVE-2020-6539, CVE-2020-6540, CVE-2020-6541"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opera-70.0.3728.133-lp152.2.15.1") ) flag++;

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
