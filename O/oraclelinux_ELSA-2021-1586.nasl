#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1586.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149947);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id(
    "CVE-2019-13012",
    "CVE-2020-9948",
    "CVE-2020-9951",
    "CVE-2020-9983",
    "CVE-2020-13543",
    "CVE-2020-13584"
  );

  script_name(english:"Oracle Linux 8 : GNOME (ELSA-2021-1586)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-1586 advisory.

  - A code execution vulnerability exists in the WebSocket functionality of Webkit WebKitGTK 2.30.0. A
    specially crafted web page can trigger a use-after-free vulnerability which can lead to remote code
    execution. An attacker can get a user to visit a webpage to trigger this vulnerability. (CVE-2020-13543)

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.1 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in a remote code execution. The
    victim needs to visit a malicious web site to trigger this vulnerability. (CVE-2020-13584)

  - The keyfile settings backend in GNOME GLib (aka glib2.0) before 2.60.0 creates directories using
    g_file_make_directory_with_parents (kfsb->dir, NULL, NULL) and files using g_file_replace_contents
    (kfsb->file, contents, length, NULL, FALSE, G_FILE_CREATE_REPLACE_DESTINATION, NULL, NULL, NULL).
    Consequently, it does not properly restrict directory (and file) permissions. Instead, for directories,
    0777 permissions are used; for files, default file permissions are used. This is similar to
    CVE-2019-12450. (CVE-2019-13012)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9948)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9951)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari
    14.0. Processing maliciously crafted web content may lead to code execution. (CVE-2020-9983)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1586.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenEXR-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenEXR-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:atkmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:atkmm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:atkmm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cairomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cairomm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cairomm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:chrome-gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dleyna-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dleyna-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:enchant2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:enchant2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gamin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gamin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geoclue2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geoclue2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geoclue2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geoclue2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geocode-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:geocode-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibmm24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibmm24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibmm24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-photos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-photos-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk2-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk2-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk2-immodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm24-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm30-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtkmm30-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdazzle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdazzle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libepubgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libepubgen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsigc++20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsigc++20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsigc++20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvisual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvisual-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pangomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pangomm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pangomm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:soundtouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:soundtouch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vala-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:woff2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:woff2-devel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'accountsservice-0.6.55-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-0.6.55-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.55-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.55-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-2.24.2-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-2.24.2-7.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-2.24.2-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-devel-2.24.2-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-devel-2.24.2-7.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-devel-2.24.2-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'atkmm-doc-2.24.2-7.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-1.12.0-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-1.12.0-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-1.12.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-devel-1.12.0-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-devel-1.12.0-8.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-devel-1.12.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cairomm-doc-1.12.0-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrome-gnome-shell-10.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrome-gnome-shell-10.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dleyna-core-0.6.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dleyna-core-0.6.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dleyna-core-0.6.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dleyna-server-0.6.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-2.2.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-2.2.3-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-2.2.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-devel-2.2.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-devel-2.2.3-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'enchant2-devel-2.2.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-0.1.10-32.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-0.1.10-32.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-0.1.10-32.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-devel-0.1.10-32.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-devel-0.1.10-32.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gamin-devel-0.1.10-32.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-3.28.3-39.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gdm-3.28.3-39.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gdm-3.28.3-39.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'geoclue2-2.5.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-2.5.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-2.5.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-demos-2.5.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-demos-2.5.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-devel-2.5.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-devel-2.5.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-devel-2.5.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-libs-2.5.5-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-libs-2.5.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geoclue2-libs-2.5.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-3.26.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-3.26.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-3.26.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-devel-3.26.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-devel-3.26.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'geocode-glib-devel-3.26.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-1.56.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-1.56.2-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-1.56.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-2.56.4-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-2.56.4-9.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-2.56.4-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-devel-2.56.4-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-devel-2.56.4-9.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-devel-2.56.4-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-doc-2.56.4-9.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-fam-2.56.4-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-fam-2.56.4-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-static-2.56.4-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-static-2.56.4-9.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-static-2.56.4-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-tests-2.56.4-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-tests-2.56.4-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-2.56.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-2.56.0-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-2.56.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-devel-2.56.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-devel-2.56.0-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-devel-2.56.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibmm24-doc-2.56.0-2.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-boxes-3.36.5-8.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-27.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-27.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-27.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-photos-3.28.1-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-photos-tests-3.28.1-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-30.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-30.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-14.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.36.1-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-3.28.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-3.28.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-nautilus-3.28.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-nautilus-3.28.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-doc-1.28-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-doc-1.28-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-2.24.32-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-2.24.32-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-2.24.32-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-devel-2.24.32-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-devel-2.24.32-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-devel-2.24.32-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-devel-docs-2.24.32-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-devel-docs-2.24.32-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodule-xim-2.24.32-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodule-xim-2.24.32-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodule-xim-2.24.32-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodules-2.24.32-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodules-2.24.32-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk2-immodules-2.24.32-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-2.24.5-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-2.24.5-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-2.24.5-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-devel-2.24.5-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-devel-2.24.5-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-devel-2.24.5-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm24-docs-2.24.5-6.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-3.22.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-3.22.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-3.22.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-devel-3.22.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-devel-3.22.2-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-devel-3.22.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtkmm30-doc-3.22.2-3.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-11.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-11.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-11.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdazzle-3.28.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdazzle-3.28.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdazzle-devel-3.28.5-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdazzle-devel-3.28.5-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepubgen-0.1.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepubgen-0.1.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepubgen-devel-0.1.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libepubgen-devel-0.1.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-3.4.5-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-3.4.5-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-3.4.5-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-devel-3.4.5-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-devel-3.4.5-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsass-devel-3.4.5-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-2.10.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-2.10.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-2.10.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-devel-2.10.0-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-devel-2.10.0-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-devel-2.10.0-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsigc++20-doc-2.10.0-6.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvisual-0.4.0-25.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libvisual-0.4.0-25.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libvisual-0.4.0-25.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libvisual-devel-0.4.0-25.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libvisual-devel-0.4.0-25.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libvisual-devel-0.4.0-25.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mutter-3.32.2-57.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-57.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-57.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-57.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-57.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-57.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-15.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-devel-2.2.0-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-devel-2.2.0-12.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-devel-2.2.0-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-libs-2.2.0-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-libs-2.2.0-12.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'OpenEXR-libs-2.2.0-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-2.40.1-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-2.40.1-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-2.40.1-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-devel-2.40.1-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-devel-2.40.1-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-devel-2.40.1-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pangomm-doc-2.40.1-6.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-2.0.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-2.0.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-2.0.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-devel-2.0.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-devel-2.0.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'soundtouch-devel-2.0.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-0.40.19-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-0.40.19-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-0.40.19-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-devel-0.40.19-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-devel-0.40.19-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-devel-0.40.19-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.30.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.30.4-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.30.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.30.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.30.4-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.30.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.30.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.30.4-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.30.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.30.4-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.30.4-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.30.4-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-1.0.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-1.0.2-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-1.0.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-devel-1.0.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-devel-1.0.2-5.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'woff2-devel-1.0.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenEXR-devel / OpenEXR-libs / accountsservice / etc');
}
