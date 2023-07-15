##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:3553. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145653);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-6251",
    "CVE-2019-8506",
    "CVE-2019-8518",
    "CVE-2019-8523",
    "CVE-2019-8524",
    "CVE-2019-8535",
    "CVE-2019-8536",
    "CVE-2019-8544",
    "CVE-2019-8558",
    "CVE-2019-8559",
    "CVE-2019-8563",
    "CVE-2019-8571",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8666",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8679",
    "CVE-2019-8681",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8726",
    "CVE-2019-8735",
    "CVE-2019-8768",
    "CVE-2019-11070",
    "CVE-2019-11459",
    "CVE-2019-12795"
  );
  script_bugtraq_id(
    108497,
    108566,
    108741,
    109328,
    109329
  );
  script_xref(name:"RHSA", value:"2019:3553");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"CentOS 8 : GNOME (CESA-2019:3553)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:3553 advisory.

  - webkitgtk: HTTP proxy setting deanonymization information disclosure (CVE-2019-11070)

  - evince: uninitialized memory use in function tiff_document_render() and tiff_document_get_thumbnail()
    (CVE-2019-11459)

  - gvfs: improper authorization in daemon/gvfsdaemon.c in gvfsd (CVE-2019-12795)

  - webkitgtk: Multiple memory corruption issues leading to arbitrary code execution (CVE-2019-6237,
    CVE-2019-8571, CVE-2019-8583, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595,
    CVE-2019-8596, CVE-2019-8597, CVE-2019-8601, CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611,
    CVE-2019-8615, CVE-2019-8619, CVE-2019-8622, CVE-2019-8623, CVE-2019-8666, CVE-2019-8671, CVE-2019-8672,
    CVE-2019-8673, CVE-2019-8676, CVE-2019-8677, CVE-2019-8679, CVE-2019-8681, CVE-2019-8686, CVE-2019-8687,
    CVE-2019-8689, CVE-2019-8726, CVE-2019-8735)

  - webkitgtk: processing maliciously crafted web content lead to URI spoofing (CVE-2019-6251)

  - webkitgtk: malicous web content leads to arbitrary code execution (CVE-2019-8506)

  - webkitgtk: malicious web content leads to arbitrary code execution (CVE-2019-8518, CVE-2019-8523,
    CVE-2019-8524, CVE-2019-8559, CVE-2019-8563)

  - webkitgtk: malicious crafted web content leads to arbitrary code execution (CVE-2019-8535, CVE-2019-8536,
    CVE-2019-8558)

  - webkitgtk: malicious crafted web content leads to arbitrary we content (CVE-2019-8544)

  - webkitgtk: Out-of-bounds read leading to memory disclosure (CVE-2019-8607)

  - webkitgtk: Incorrect state management leading to universal cross-site scripting (CVE-2019-8690)

  - webkitgtk: Browsing history could not be deleted (CVE-2019-8768)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3553");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8689");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-8735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:SDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:baobab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:chrome-gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-xlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-xlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-desktop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-desktop3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-drive-menu");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-tweaks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs60-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-core-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-graphics-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-fade-throbber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-label");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-space-flares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-throbgress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-plugin-two-step");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-system-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-charge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-fade-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-solar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-spinfinity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:plymouth-theme-spinner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wayland-protocols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:webkit2gtk3-plugin-process-gtk2");
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
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'accountsservice-0.6.50-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-0.6.50-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.50-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.50-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.50-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.50-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'appstream-data-8-20190805.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'appstream-data-8-20190805.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'baobab-3.28.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'baobab-3.28.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrome-gnome-shell-10.1-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chrome-gnome-shell-10.1-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-3.28.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-3.28.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'file-roller-3.28.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'file-roller-3.28.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-2.36.12-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-devel-2.36.12-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-devel-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-modules-2.36.12-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-modules-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-2.36.12-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-devel-2.36.12-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdk-pixbuf2-xlib-devel-2.36.12-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-3.28.3-22.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gdm-3.28.3-22.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gjs-1.56.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-1.56.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-classic-session-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-3.32.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-3.32.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-devel-3.32.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-desktop3-devel-3.32.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-remote-desktop-0.1.6-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-remote-desktop-0.1.6-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-settings-daemon-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-apps-menu-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-auto-move-windows-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-common-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-dash-to-dock-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-desktop-icons-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-disable-screenshield-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-drive-menu-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-horizontal-workspaces-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-launch-new-instance-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-native-window-placement-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-no-hot-corner-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-panel-favorites-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-places-menu-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-systemMonitor-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-top-icons-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-updates-dialog-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-user-theme-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-grouper-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-window-list-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-windowsNavigator-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-extension-workspace-indicator-3.32.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.30.6-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.30.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-editor-3.30.6-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-editor-3.30.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-tweaks-3.28.1-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-tweaks-3.28.1-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-2.13.0-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-devel-2.13.0-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpurple-devel-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-60.9.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-60.9.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-devel-60.9.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-devel-60.9.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pango-1.42.4-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pango-1.42.4-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pango-devel-1.42.4-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pango-devel-1.42.4-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-2.13.0-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-devel-2.13.0-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pidgin-devel-2.13.0-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-core-libs-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-core-libs-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-graphics-libs-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-graphics-libs-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-fade-throbber-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-fade-throbber-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-label-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-label-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-script-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-script-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-space-flares-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-space-flares-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-throbgress-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-throbgress-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-two-step-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-plugin-two-step-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-scripts-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-scripts-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-system-theme-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-system-theme-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-charge-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-charge-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-fade-in-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-fade-in-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-script-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-script-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-solar-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-solar-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-spinfinity-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-spinfinity-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-spinner-0.9.3-15.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plymouth-theme-spinner-0.9.3-15.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'SDL-1.2.15-35.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'SDL-1.2.15-35.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'SDL-devel-1.2.15-35.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'SDL-devel-1.2.15-35.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wayland-protocols-devel-1.17-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wayland-protocols-devel-1.17-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.24.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-2.24.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.24.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-devel-2.24.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.24.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-2.24.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.24.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-jsc-devel-2.24.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-plugin-process-gtk2-2.24.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkit2gtk3-plugin-process-gtk2-2.24.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'SDL / SDL-devel / accountsservice / accountsservice-devel / etc');
}
