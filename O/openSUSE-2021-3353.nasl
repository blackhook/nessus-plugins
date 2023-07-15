#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3353-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154105);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-21806", "CVE-2021-30858");
  script_xref(name:"IAVA", value:"2021-A-0414-S");
  script_xref(name:"IAVA", value:"2021-A-0437-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE 15 Security Update : webkit2gtk3 (openSUSE-SU-2021:3353-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3353-1 advisory.

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.3 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in remote code execution. The victim
    needs to visit a malicious web site to trigger the vulnerability. (CVE-2021-21806)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and
    iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been actively exploited. (CVE-2021-30858)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190701");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4KJIY3NX4MIKAMIQIFUSKB4JVJBMJUFI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fdeef26");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30858");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.32.4-12.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebkit2gtk-4_0-37-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebkit2gtk-4_0-37-32bit-2.32.4-12.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebkit2gtk3-lang-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-WebKit2-4_0-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit-jsc-4-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-minibrowser-2.32.4-12.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc');
}
