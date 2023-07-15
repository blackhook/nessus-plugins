#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:4381.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157596);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-13558",
    "CVE-2020-24870",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2020-36241",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-1871",
    "CVE-2021-21775",
    "CVE-2021-21779",
    "CVE-2021-21806",
    "CVE-2021-28650",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30682",
    "CVE-2021-30689",
    "CVE-2021-30720",
    "CVE-2021-30734",
    "CVE-2021-30744",
    "CVE-2021-30749",
    "CVE-2021-30758",
    "CVE-2021-30795",
    "CVE-2021-30797",
    "CVE-2021-30799"
  );
  script_xref(name:"ALSA", value:"2021:4381");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0212-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"AlmaLinux 8 : GNOME (ALSA-2021:4381)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:4381 advisory.

  - A code execution vulnerability exists in the AudioSourceProviderGStreamer functionality of Webkit
    WebKitGTK 2.30.1. A specially crafted web page can lead to a use after free. (CVE-2020-13558)

  - Libraw before 0.20.1 has a stack buffer overflow via LibRaw::identify_process_dng_fields in identify.cpp.
    (CVE-2020-24870)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Big Sur
    11.0.1, watchOS 7.1, iOS 14.2 and iPadOS 14.2, iCloud for Windows 11.5, Safari 14.0.1, tvOS 14.2, iTunes
    12.11 for Windows. Processing maliciously crafted web content may lead to arbitrary code execution.
    (CVE-2020-27918)

  - Clear History and Website Data did not clear the history. The issue was addressed with improved data
    deletion. This issue is fixed in macOS Big Sur 11.1, Security Update 2020-001 Catalina, Security Update
    2020-007 Mojave, iOS 14.3 and iPadOS 14.3, tvOS 14.3. A user may be unable to fully delete browsing
    history. (CVE-2020-29623)

  - autoar-extractor.c in GNOME gnome-autoar through 0.2.4, as used by GNOME Shell, Nautilus, and other
    software, allows Directory Traversal during extraction because it lacks a check of whether a file's parent
    is a symlink to a directory outside of the intended extraction location. (CVE-2020-36241)

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

  - A use-after-free vulnerability exists in the way certain events are processed for ImageLoader objects of
    Webkit WebKitGTK 2.30.4. A specially crafted web page can lead to a potential information leak and further
    memory corruption. In order to trigger the vulnerability, a victim must be tricked into visiting a
    malicious webpage. (CVE-2021-21775)

  - A use-after-free vulnerability exists in the way Webkit's GraphicsContext handles certain events in
    WebKitGTK 2.30.4. A specially crafted web page can lead to a potential information leak and further memory
    corruption. A victim must be tricked into visiting a malicious web page to trigger this vulnerability.
    (CVE-2021-21779)

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.3 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in remote code execution. The victim
    needs to visit a malicious web site to trigger the vulnerability. (CVE-2021-21806)

  - autoar-extractor.c in GNOME gnome-autoar before 0.3.1, as used by GNOME Shell, Nautilus, and other
    software, allows Directory Traversal during extraction because it lacks a check of whether a file's parent
    is a symlink in certain complex situations. NOTE: this issue exists because of an incomplete fix for
    CVE-2020-36241. (CVE-2021-28650)

  - An integer overflow was addressed with improved input validation. This issue is fixed in iOS 14.5.1 and
    iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, Safari 14.1.1, macOS Big Sur 11.3.1. Processing maliciously crafted
    web content may lead to arbitrary code execution. (CVE-2021-30663)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS
    7.4.1, iOS 14.5.1 and iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, macOS Big Sur 11.3.1. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30665)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious application may be able to leak
    sensitive user information. (CVE-2021-30682)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. Processing maliciously crafted web content
    may lead to universal cross site scripting. (CVE-2021-30689)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 14.6, iOS 14.6 and
    iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. A malicious website may be able to access
    restricted ports on arbitrary servers. (CVE-2021-30720)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in
    tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4, watchOS 7.5. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30734, CVE-2021-30749)

  - Description: A cross-origin issue with iframe elements was addressed with improved tracking of security
    origins. This issue is fixed in tvOS 14.6, iOS 14.6 and iPadOS 14.6, Safari 14.1.1, macOS Big Sur 11.4,
    watchOS 7.5. Processing maliciously crafted web content may lead to universal cross site scripting.
    (CVE-2021-30744)

  - A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 14.7, Safari
    14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to
    arbitrary code execution. (CVE-2021-30758)

  - A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.7,
    Safari 14.1.2, macOS Big Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-30795)

  - This issue was addressed with improved checks. This issue is fixed in iOS 14.7, Safari 14.1.2, macOS Big
    Sur 11.5, watchOS 7.6, tvOS 14.7. Processing maliciously crafted web content may lead to code execution.
    (CVE-2021-30797)

  - Multiple memory corruption issues were addressed with improved memory handling. This issue is fixed in iOS
    14.7, macOS Big Sur 11.5, Security Update 2021-004 Catalina, Security Update 2021-005 Mojave. Processing
    maliciously crafted web content may lead to arbitrary code execution. (CVE-2021-30799)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-4381.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30799");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-autoar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-calculator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-session-kiosk-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-gesture-inhibitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gnome-software-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'accountsservice-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-40.0-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gdm-40.0-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-28.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-kiosk-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-40.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-gesture-inhibitor-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-20.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-3.22.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.32.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / accountsservice / accountsservice-devel / etc');
}
