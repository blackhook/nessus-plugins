#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1990-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150913);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-9947",
    "CVE-2020-9948",
    "CVE-2020-9951",
    "CVE-2020-9983",
    "CVE-2020-13543",
    "CVE-2020-13558",
    "CVE-2020-13584",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-1871"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1990-1");
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : webkit2gtk3 (SUSE-SU-2021:1990-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:1990-1 advisory.

  - A code execution vulnerability exists in the WebSocket functionality of Webkit WebKitGTK 2.30.0. A
    specially crafted web page can trigger a use-after-free vulnerability which can lead to remote code
    execution. An attacker can get a user to visit a webpage to trigger this vulnerability. (CVE-2020-13543)

  - A code execution vulnerability exists in the AudioSourceProviderGStreamer functionality of Webkit
    WebKitGTK 2.30.1. A specially crafted web page can lead to a use after free. (CVE-2020-13558)

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.1 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in a remote code execution. The
    victim needs to visit a malicious web site to trigger this vulnerability. (CVE-2020-13584)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.0.1, watchOS 7.1, iOS 14.2 and iPadOS 14.2, iCloud for Windows 11.5, Safari 14.0.1, tvOS 14.2, iTunes
    12.11 for Windows. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-27918)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Big Sur 11.1, Security Update 2020-001 Catalina, Security Update
    2020-007 Mojave, iOS 14.3 and iPadOS 14.3, tvOS 14.3. A user may be unable to fully delete browsing
    history. (CVE-2020-29623)

  - A use after free issue was addressed with improved memory management. This issue is fixed in watchOS 7.0,
    iOS 14.0 and iPadOS 14.0, iTunes for Windows 12.10.9, iCloud for Windows 11.5, tvOS 14.0, Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9947)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9948)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9951)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari
    14.0. Processing maliciously crafted web content may lead to code execution. (CVE-2020-9983)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave. Maliciously crafted web content
    may violate iframe sandboxing policy. (CVE-2021-1765)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1788)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4
    and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2021-1789)

  - A port redirection issue was addressed with additional port validation. This issue is fixed in macOS Big
    Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS
    14.4 and iPadOS 14.4, Safari 14.0.3. A malicious website may be able to access restricted ports on
    arbitrary servers. (CVE-2021-1799)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in macOS Big Sur
    11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, watchOS 7.3, tvOS 14.4, iOS 14.4
    and iPadOS 14.4. Maliciously crafted web content may violate iframe sandboxing policy. (CVE-2021-1801)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 14.4.1 and
    iPadOS 14.4.1, Safari 14.0.3 (v. 14610.4.3.1.7 and 15610.4.3.1.7), watchOS 7.3.2, macOS Big Sur 11.2.3.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-1844)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.2,
    Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, iOS 14.4 and iPadOS 14.4. A remote
    attacker may be able to cause arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-1870, CVE-2021-1871)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184262");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/009023.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01d3fe47");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1871");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + sp);
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'webkit2gtk3-devel-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.2'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'webkit2gtk3-devel-2.32.1-2.63', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'webkit2gtk3-devel-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'webkit2gtk3-devel-2.32.1-2.63', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libwebkit2gtk-4_0-37-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libwebkit2gtk3-lang-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.1-2.63', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjavascriptcoregtk-4_0-18 / libwebkit2gtk-4_0-37 / etc');
}
