#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-60.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(132949);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17015",
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17021",
    "CVE-2019-17022",
    "CVE-2019-17024",
    "CVE-2019-17026"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-60)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaFirefox fixes the following issues :

  - Firefox Extended Support Release 68.4.1 ESR

  - Fixed: Security fix MFSA 2020-03 (bsc#1160498)

  - CVE-2019-17026 (bmo#1607443) IonMonkey type confusion
    with StoreElementHole and FallibleStoreElement 

  - Firefox Extended Support Release 68.4.0 ESR

  - Fixed: Various security fixes MFSA 2020-02 (bsc#1160305)

  - CVE-2019-17015 (bmo#1599005) Memory corruption in parent
    process during new content process initialization on
    Windows

  - CVE-2019-17016 (bmo#1599181) Bypass of @namespace CSS
    sanitization during pasting

  - CVE-2019-17017 (bmo#1603055) Type Confusion in
    XPCVariant.cpp

  - CVE-2019-17021 (bmo#1599008) Heap address disclosure in
    parent process during content process initialization on
    Windows

  - CVE-2019-17022 (bmo#1602843) CSS sanitization does not
    escape HTML tags

  - CVE-2019-17024 (bmo#1507180, bmo#1595470, bmo#1598605,
    bmo#1601826) Memory safety bugs fixed in Firefox 72 and
    Firefox ESR 68.4

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160498");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-branding-upstream-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-buildsymbols-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debuginfo-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-debugsource-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-devel-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-common-68.4.1-lp151.2.24.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"MozillaFirefox-translations-other-68.4.1-lp151.2.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
