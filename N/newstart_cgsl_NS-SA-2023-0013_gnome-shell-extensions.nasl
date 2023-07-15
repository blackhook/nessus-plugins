#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0013. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174070);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2018-5818", "CVE-2018-5819", "CVE-2019-3820");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : gnome-shell-extensions Multiple Vulnerabilities (NS-SA-2023-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has gnome-shell-extensions packages installed that
are affected by multiple vulnerabilities:

  - An error within the parse_rollei() function (internal/dcraw_common.cpp) within LibRaw versions prior to
    0.19.1 can be exploited to trigger an infinite loop. (CVE-2018-5818)

  - An error within the parse_sinar_ia() function (internal/dcraw_common.cpp) within LibRaw versions prior
    to 0.19.1 can be exploited to exhaust available CPU resources. (CVE-2018-5819)

  - It was discovered that the gnome-shell lock screen since version 3.15.91 did not properly restrict all
    contextual actions. An attacker with physical access to a locked workstation could invoke certain keyboard
    shortcuts, and potentially other actions. (CVE-2019-3820)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0013");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-5818");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-5819");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-3820");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL gnome-shell-extensions packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3820");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-alternate-tab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-extra-osk-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-alternate-tab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-extra-osk-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'gnome-classic-session-3.28.1-17.el7_9',
    'gnome-shell-extension-alternate-tab-3.28.1-17.el7_9',
    'gnome-shell-extension-apps-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-auto-move-windows-3.28.1-17.el7_9',
    'gnome-shell-extension-common-3.28.1-17.el7_9',
    'gnome-shell-extension-dash-to-dock-3.28.1-17.el7_9',
    'gnome-shell-extension-disable-screenshield-3.28.1-17.el7_9',
    'gnome-shell-extension-drive-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-extra-osk-keys-3.28.1-17.el7_9',
    'gnome-shell-extension-horizontal-workspaces-3.28.1-17.el7_9',
    'gnome-shell-extension-launch-new-instance-3.28.1-17.el7_9',
    'gnome-shell-extension-native-window-placement-3.28.1-17.el7_9',
    'gnome-shell-extension-no-hot-corner-3.28.1-17.el7_9',
    'gnome-shell-extension-panel-favorites-3.28.1-17.el7_9',
    'gnome-shell-extension-places-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-screenshot-window-sizer-3.28.1-17.el7_9',
    'gnome-shell-extension-systemMonitor-3.28.1-17.el7_9',
    'gnome-shell-extension-top-icons-3.28.1-17.el7_9',
    'gnome-shell-extension-updates-dialog-3.28.1-17.el7_9',
    'gnome-shell-extension-user-theme-3.28.1-17.el7_9',
    'gnome-shell-extension-window-grouper-3.28.1-17.el7_9',
    'gnome-shell-extension-window-list-3.28.1-17.el7_9',
    'gnome-shell-extension-windowsNavigator-3.28.1-17.el7_9',
    'gnome-shell-extension-workspace-indicator-3.28.1-17.el7_9'
  ],
  'CGSL MAIN 5.05': [
    'gnome-classic-session-3.28.1-17.el7_9',
    'gnome-shell-extension-alternate-tab-3.28.1-17.el7_9',
    'gnome-shell-extension-apps-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-auto-move-windows-3.28.1-17.el7_9',
    'gnome-shell-extension-common-3.28.1-17.el7_9',
    'gnome-shell-extension-dash-to-dock-3.28.1-17.el7_9',
    'gnome-shell-extension-disable-screenshield-3.28.1-17.el7_9',
    'gnome-shell-extension-drive-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-extra-osk-keys-3.28.1-17.el7_9',
    'gnome-shell-extension-horizontal-workspaces-3.28.1-17.el7_9',
    'gnome-shell-extension-launch-new-instance-3.28.1-17.el7_9',
    'gnome-shell-extension-native-window-placement-3.28.1-17.el7_9',
    'gnome-shell-extension-no-hot-corner-3.28.1-17.el7_9',
    'gnome-shell-extension-panel-favorites-3.28.1-17.el7_9',
    'gnome-shell-extension-places-menu-3.28.1-17.el7_9',
    'gnome-shell-extension-screenshot-window-sizer-3.28.1-17.el7_9',
    'gnome-shell-extension-systemMonitor-3.28.1-17.el7_9',
    'gnome-shell-extension-top-icons-3.28.1-17.el7_9',
    'gnome-shell-extension-updates-dialog-3.28.1-17.el7_9',
    'gnome-shell-extension-user-theme-3.28.1-17.el7_9',
    'gnome-shell-extension-window-grouper-3.28.1-17.el7_9',
    'gnome-shell-extension-window-list-3.28.1-17.el7_9',
    'gnome-shell-extension-windowsNavigator-3.28.1-17.el7_9',
    'gnome-shell-extension-workspace-indicator-3.28.1-17.el7_9'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gnome-shell-extensions');
}
