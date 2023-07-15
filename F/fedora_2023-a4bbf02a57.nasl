#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-a4bbf02a57
#

include('compat.inc');

if (description)
{
  script_id(174958);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/30");

  script_cve_id(
    "CVE-2022-0108",
    "CVE-2022-32885",
    "CVE-2023-25358",
    "CVE-2023-27932",
    "CVE-2023-27954",
    "CVE-2023-28205"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/01");
  script_xref(name:"FEDORA", value:"2023-a4bbf02a57");

  script_name(english:"Fedora 37 : webkitgtk (2023-a4bbf02a57)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-a4bbf02a57 advisory.

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.7.5
    and iPadOS 15.7.5, Safari 16.4.1, iOS 16.4.1 and iPadOS 16.4.1, macOS Ventura 13.3.1. Processing
    maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this
    issue may have been actively exploited. (CVE-2023-28205)

  - Inappropriate implementation in Navigation in Google Chrome prior to 97.0.4692.71 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-0108)

  - A use-after-free vulnerability in WebCore::RenderLayer::addChild in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25358)

  -  * The Bubblewrap sandbox no longer requires setting an application identifier via GApplication to operate
    correctly. Using GApplication is still recommended, but optional.  * Adjust the scrolling speed for mouse
    wheels to make it feel more natural.  * Allow pasting content using the Asynchronous Clipboard API when
    the origin is the same as the clipboard contents.  * Improvements to the GStreamer multimedia playback, in
    particular around MSE, WebRTC, and seeking.  * Make all supported image types appear in the Accept HTTP
    header.  * Fix text caret blinking when blinking is disabled in the GTK settings.  * Fix default database
    quota size definition.  * Fix application of all caps tags listed in the font-feature-settings CSS
    property.  * Fix font height calculations for the font-size-adjust CSS property.  * Fix several crashes
    and rendering issues.  * Security fixes: CVE-2022-0108, CVE-2022-32885, CVE-2023-25358, CVE-2023-27932,
    CVE-2023-27954, CVE-2023-28205  (CVE-2022-32885)

  - This issue was addressed with improved state management. (CVE-2023-27932)

  - The issue was addressed by removing origin information. (CVE-2023-27954)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-a4bbf02a57");
  script_set_attribute(attribute:"solution", value:
"Update the affected webkitgtk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0108");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'webkitgtk-2.40.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkitgtk');
}
