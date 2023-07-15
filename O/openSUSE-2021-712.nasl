#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-712.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150103);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-21206",
    "CVE-2021-21220",
    "CVE-2021-21222",
    "CVE-2021-21223",
    "CVE-2021-21224",
    "CVE-2021-21225",
    "CVE-2021-21226"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2021-712)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for opera fixes the following issues :

Update to version 76.0.4017.94

  - released on the stable branch

Update to version 76.0.4017.88

  - CHR-8404 Update chromium on desktop-stable-90-4017 to
    90.0.4430.85

  - DNA-92219 Add bookmark API supports to the front-end

  - DNA-92409 [MAC] &lsquo;Present now&rsquo; options
    windows appear behind detached window

  - DNA-92615 Capture tab from the tab context menu

  - DNA-92616 Capture tab from Snapshot

  - DNA-92617 Capture tab from image context menu

  - DNA-92652 Opera 76 translations

  - DNA-92680 Make image selector on any page work like
    bookmarks popup WP2

  - DNA-92707 Crash at void
    base::ObserverList::AddObserver(class
    content::PrerenderHost::Observer*)

  - DNA-92710 Autoupdate on macOS 11.3 not working

  - DNA-92711 Make image selector on any page work like
    bookmarks popup WP3

  - DNA-92730 Make image selector on any page work like
    bookmarks popup WP4

  - DNA-92761 Make image selector on any page work like
    bookmarks popup WP5

  - DNA-92776 Make image selector on any page work like
    bookmarks popup WP6

  - DNA-92862 Make &ldquo;View pinboards&rdquo; button work

  - DNA-92906 Provide in-house translations for Cashback
    strings to Spanish

  - DNA-92908 API collides with oneclick installer

  - The update to chromium 90.0.4430.85 fixes following
    issues :

  - CVE-2021-21222, CVE-2021-21223, CVE-2021-21224,
    CVE-2021-21225, CVE-2021-21226

  - Complete Opera 76.0 changelog at:
    https://blogs.opera.com/desktop/changelog-for-76/

Update to version 75.0.3969.218

  - CHR-8393 Update chromium on desktop-stable-89-3969 to
    89.0.4389.128

  - DNA-92113 Windows debug fails to compile
    opera_components/ipfs/ipfs/ipfs_url_loader_throttle.obj

  - DNA-92198 [Arm] Update signing scripts

  - DNA-92200 [Arm] Create universal packages from two
    buildsets

  - DNA-92338 [Search tabs] The preview isn&rsquo;t updated
    when the tab from another window is closed

  - DNA-92410 [Download popup] Selected item still looks bad
    in dark mode

  - DNA-92441 Compilation error

  - DNA-92514 Allow to generate universal DMG package from
    existing universal .tar.xz

  - DNA-92608 Opera 75 crash during rapid workspace
    switching

  - DNA-92627 Crash at automation::Error::code()

  - DNA-92630 Crash at
    opera::PremiumExtensionPersistentPrefStorageImpl::IsPrem
    iumExtensionFeatureEnabled()

  - DNA-92648 Amazon icon disappears from Sidebar Extensions
    section after pressing Hide Amazon button

  - DNA-92681 Add missing string in Japanese

  - DNA-92684 Fix issues with signing multiple bsids

  - DNA-92706 Update repack generation from universal
    packages

  - DNA-92725 Enable IPFS for all channels

  - The update to chromium 89.0.4389.128 fixes following
    issues: CVE-2021-21206, CVE-2021-21220");
  script_set_attribute(attribute:"see_also", value:"https://blogs.opera.com/desktop/changelog-for-76/");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 89.0.4389.128 V8 XOR Typer Out-Of-Bounds Access RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");

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

if ( rpm_check(release:"SUSE15.2", reference:"opera-76.0.4017.94-lp152.2.43.1") ) flag++;

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
