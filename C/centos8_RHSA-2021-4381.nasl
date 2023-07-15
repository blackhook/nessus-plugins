#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:4381. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155097);
  script_version("1.9");
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
  script_xref(name:"RHSA", value:"2021:4381");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"IAVA", value:"2021-A-0126-S");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0212-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"CentOS 8 : GNOME (CESA-2021:4381)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:4381 advisory.

  - webkitgtk: Use-after-free in AudioSourceProviderGStreamer leading to arbitrary code execution
    (CVE-2020-13558)

  - LibRaw: Stack buffer overflow in LibRaw::identify_process_dng_fields() in identify.cpp (CVE-2020-24870)

  - webkitgtk: Use-after-free leading to arbitrary code execution (CVE-2020-27918, CVE-2021-1788,
    CVE-2021-30795)

  - webkitgtk: User may be unable to fully delete browsing history (CVE-2020-29623)

  - CVE-2021-28650 gnome-autoar: Directory traversal via directory symbolic links pointing outside of the
    destination directory (incomplete  fix) (CVE-2020-36241)

  - webkitgtk: IFrame sandboxing policy violation (CVE-2021-1765, CVE-2021-1801)

  - webkitgtk: Type confusion issue leading to arbitrary code execution (CVE-2021-1789)

  - webkitgtk: Access to restricted ports on arbitrary servers via port redirection (CVE-2021-1799)

  - webkitgtk: Memory corruption issue leading to arbitrary code execution (CVE-2021-1844)

  - webkitgtk: Logic issue leading to arbitrary code execution (CVE-2021-1870, CVE-2021-1871)

  - webkitgtk: Use-after-free in ImageLoader dispatchPendingErrorEvent leading to information leak and
    possibly code execution (CVE-2021-21775)

  - webkitgtk: Use-after-free in WebCore::GraphicsContext leading to information leak and possibly code
    execution (CVE-2021-21779)

  - webkitgtk: Use-after-free in fireEventListeners leading to arbitrary code execution (CVE-2021-21806)

  - gnome-autoar: Directory traversal via directory symbolic links pointing outside of the destination
    directory (incomplete CVE-2020-36241 fix) (CVE-2021-28650)

  - webkitgtk: Integer overflow leading to arbitrary code execution (CVE-2021-30663)

  - webkitgtk: Memory corruption leading to arbitrary code execution (CVE-2021-30665)

  - webkitgtk: Logic issue leading to leak of sensitive user information (CVE-2021-30682)

  - webkitgtk: Logic issue leading to universal cross site scripting attack (CVE-2021-30689)

  - webkitgtk: Logic issue allowing access to restricted ports on arbitrary servers (CVE-2021-30720)

  - webkitgtk: Memory corruptions leading to arbitrary code execution (CVE-2021-30734, CVE-2021-30749,
    CVE-2021-30799)

  - webkitgtk: Cross-origin issue with iframe elements leading to universal cross site scripting attack
    (CVE-2021-30744)

  - webkitgtk: Type confusion leading to arbitrary code execution (CVE-2021-30758)

  - webkitgtk: Insufficient checks leading to arbitrary code execution (CVE-2021-30797)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4381");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-autoar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-calculator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-kiosk-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-gesture-inhibitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vino");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'accountsservice-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-autoar-0.2.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-calculator-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-28.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-28.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-28.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-kiosk-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-kiosk-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-13.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-13.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-40.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-40.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-gesture-inhibitor-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-gesture-inhibitor-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-20.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-20.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-devel-3.36.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-60.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-3.22.0-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vino-3.22.0-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
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
