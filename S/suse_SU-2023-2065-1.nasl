#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2065-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(174948);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/29");

  script_cve_id(
    "CVE-2022-0108",
    "CVE-2022-32885",
    "CVE-2022-32886",
    "CVE-2022-32912",
    "CVE-2023-25358",
    "CVE-2023-25360",
    "CVE-2023-25361",
    "CVE-2023-25362",
    "CVE-2023-25363",
    "CVE-2023-27932",
    "CVE-2023-27954",
    "CVE-2023-28205"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2065-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/01");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : webkit2gtk3 (SUSE-SU-2023:2065-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2065-1 advisory.

  - Inappropriate implementation in Navigation in Google Chrome prior to 97.0.4692.71 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2022-0108)

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

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in Safari 16, iOS
    16, iOS 15.7 and iPadOS 15.7. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2022-32886)

  - An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in Safari 16, iOS
    16, iOS 15.7 and iPadOS 15.7. Processing maliciously crafted web content may lead to arbitrary code
    execution. (CVE-2022-32912)

  - A use-after-free vulnerability in WebCore::RenderLayer::addChild in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25358)

  - A use-after-free vulnerability in WebCore::RenderLayer::renderer in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25360)

  - A use-after-free vulnerability in WebCore::RenderLayer::setNextSibling in WebKitGTK before 2.36.8 allows
    attackers to execute code remotely. (CVE-2023-25361)

  - A use-after-free vulnerability in WebCore::RenderLayer::repaintBlockSelectionGaps in WebKitGTK before
    2.36.8 allows attackers to execute code remotely. (CVE-2023-25362)

  - A use-after-free vulnerability in WebCore::RenderLayer::updateDescendantDependentFlags in WebKitGTK before
    2.36.8 allows attackers to execute code remotely. (CVE-2023-25363)

  - This issue was addressed with improved state management. (CVE-2023-27932)

  - The issue was addressed by removing origin information. (CVE-2023-27954)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 15.7.5
    and iPadOS 15.7.5, Safari 16.4.1, iOS 16.4.1 and iPadOS 16.4.1, macOS Ventura 13.3.1. Processing
    maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this
    issue may have been actively exploited. (CVE-2023-28205)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210731");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-April/014671.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89102f46");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-32912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25360");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25363");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-27954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28205");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0108");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-5_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-5_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-5_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-5_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_1-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-5_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-soup2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libjavascriptcoregtk-5_0-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libjavascriptcoregtk-5_0-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-4_0-37-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-4_0-37-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-4_1-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-4_1-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-5_0-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libwebkit2gtk-5_0-0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-5_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-5_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-5_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-5_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-5_0-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk-5_0-injected-bundles-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk3-devel-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk3-devel-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk3-soup2-devel-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'webkit2gtk3-soup2-devel-2.38.6-150400.4.39.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'WebKit2GTK-4.0-lang-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'WebKit2GTK-4.1-lang-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'WebKit2GTK-5.0-lang-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.38.6-150400.4.39.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_1-0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libjavascriptcoregtk-4_1-0-32bit-2.38.6-150400.4.39.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libjavascriptcoregtk-5_0-0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libwebkit2gtk-4_0-37-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libwebkit2gtk-4_0-37-32bit-2.38.6-150400.4.39.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libwebkit2gtk-4_1-0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libwebkit2gtk-4_1-0-32bit-2.38.6-150400.4.39.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libwebkit2gtk-5_0-0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-4_1-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-JavaScriptCore-5_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-4_1-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2-5_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_1-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'typelib-1_0-WebKit2WebExtension-5_0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit-jsc-4-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit-jsc-4.1-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit-jsc-5.0-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk-4_1-injected-bundles-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk-5_0-injected-bundles-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk3-devel-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk3-minibrowser-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk3-soup2-devel-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk3-soup2-minibrowser-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk4-devel-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'webkit2gtk4-minibrowser-2.38.6-150400.4.39.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'WebKit2GTK-4.0-lang / WebKit2GTK-4.1-lang / WebKit2GTK-5.0-lang / etc');
}
