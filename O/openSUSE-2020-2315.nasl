#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2315.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145368);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

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

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-2315)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaFirefox fixes the following issues :

  - Firefox Extended Support Release 78.5.0 ESR
    (bsc#1178824)

  - CVE-2020-26951: Parsing mismatches could confuse and
    bypass security sanitizer for chrome privileged code

  - CVE-2020-16012: Variable time processing of cross-origin
    images during drawImage calls

  - CVE-2020-26953: Fullscreen could be enabled without
    displaying the security UI

  - CVE-2020-26956: XSS through paste (manual and clipboard
    API)

  - CVE-2020-26958: Requests intercepted through
    ServiceWorkers lacked MIME type restrictions

  - CVE-2020-26959: Use-after-free in WebRequestService

  - CVE-2020-26960: Potential use-after-free in uses of
    nsTArray

  - CVE-2020-15999: Heap buffer overflow in freetype

  - CVE-2020-26961: DoH did not filter IPv4 mapped IP
    Addresses

  - CVE-2020-26965: Software keyboards may have remembered
    typed passwords

  - CVE-2020-26966: Single-word search queries were also
    broadcast to local network

  - CVE-2020-26968: Memory safety bugs fixed in Firefox 83
    and Firefox ESR 78.5

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178824");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
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

if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-branding-upstream-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-buildsymbols-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debuginfo-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debugsource-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-devel-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-common-78.5.0-lp152.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-other-78.5.0-lp152.2.33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
