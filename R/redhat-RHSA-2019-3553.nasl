#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3553. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130552);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2019-11459", "CVE-2019-12795");
  script_xref(name:"RHSA", value:"2019:3553");

  script_name(english:"RHEL 8 : GNOME (RHSA-2019:3553)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for GNOME is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

GNOME is the default desktop environment of Red Hat Enterprise Linux.

Security Fix(es) :

* evince: uninitialized memory use in function tiff_document_render()
and tiff_document_get_thumbnail() (CVE-2019-11459)

* gvfs: improper authorization in daemon/gvfsdaemon.c in gvfsd
(CVE-2019-12795)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-12795"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SDL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SDL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SDL-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:SDL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:accountsservice-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:baobab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:baobab-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:baobab-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chrome-gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-browser-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evince-nautilus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-roller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-roller-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-xlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-xlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-xlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gjs-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-desktop3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-desktop3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-desktop3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-desktop3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-desktop3-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-remote-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-remote-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-settings-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-settings-daemon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-software-editor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-tweaks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk-update-icon-cache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-immodule-xim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-immodules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gtk3-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-afp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-archive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-goa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-gphoto2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-mtp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gvfs-smb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozjs60-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mutter-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nautilus-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pango-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pango-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pango-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-core-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-core-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-graphics-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-graphics-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-fade-throbber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-fade-throbber-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-label");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-label-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-script-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-space-flares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-space-flares-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-throbgress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-throbgress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-two-step");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-plugin-two-step-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-system-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-charge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-fade-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-solar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-spinfinity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plymouth-theme-spinner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wayland-protocols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-jsc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-plugin-process-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkit2gtk3-plugin-process-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3553";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"SDL-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"SDL-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"SDL-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"SDL-debuginfo-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"SDL-debuginfo-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"SDL-debuginfo-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"SDL-debugsource-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"SDL-debugsource-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"SDL-debugsource-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"SDL-devel-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"SDL-devel-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"SDL-devel-1.2.15-35.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"accountsservice-debuginfo-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-debuginfo-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"accountsservice-debugsource-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-debugsource-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"accountsservice-devel-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-devel-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"accountsservice-libs-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-libs-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"accountsservice-libs-debuginfo-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"accountsservice-libs-debuginfo-0.6.50-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"appstream-data-8-20190805.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"baobab-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"baobab-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"baobab-debuginfo-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"baobab-debuginfo-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"baobab-debugsource-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"baobab-debugsource-3.28.0-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"chrome-gnome-shell-10.1-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-browser-plugin-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-browser-plugin-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-browser-plugin-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-browser-plugin-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-debugsource-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-debugsource-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-debugsource-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-libs-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-libs-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-libs-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-libs-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-libs-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-libs-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-nautilus-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"evince-nautilus-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"evince-nautilus-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"evince-nautilus-debuginfo-3.28.4-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"file-roller-3.28.1-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"file-roller-debuginfo-3.28.1-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"file-roller-debugsource-3.28.1-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"finch-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"finch-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"finch-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"finch-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-debugsource-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-debugsource-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-debugsource-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-debugsource-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-devel-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-devel-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-devel-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-devel-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-modules-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-modules-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-modules-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-modules-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-modules-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-modules-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-modules-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-tests-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-tests-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-tests-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-tests-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-xlib-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-xlib-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-xlib-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-xlib-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-xlib-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-xlib-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-xlib-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-xlib-debuginfo-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gdk-pixbuf2-xlib-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdk-pixbuf2-xlib-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gdk-pixbuf2-xlib-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdk-pixbuf2-xlib-devel-2.36.12-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdm-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdm-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdm-debuginfo-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdm-debuginfo-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gdm-debugsource-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gdm-debugsource-3.28.3-22.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gjs-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gjs-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gjs-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gjs-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gjs-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gjs-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gjs-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gjs-debugsource-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gjs-debugsource-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gjs-debugsource-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gjs-debugsource-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gjs-devel-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gjs-devel-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gjs-devel-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gjs-devel-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"gjs-tests-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gjs-tests-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gjs-tests-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gjs-tests-debuginfo-1.56.2-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-classic-session-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-control-center-3.28.2-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-control-center-debuginfo-3.28.2-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-control-center-debugsource-3.28.2-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-control-center-filesystem-3.28.2-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gnome-desktop3-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-desktop3-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gnome-desktop3-debuginfo-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-desktop3-debuginfo-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gnome-desktop3-debugsource-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-desktop3-debugsource-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gnome-desktop3-devel-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-desktop3-devel-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gnome-desktop3-tests-debuginfo-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-desktop3-tests-debuginfo-3.32.2-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-remote-desktop-0.1.6-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-remote-desktop-debuginfo-0.1.6-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-remote-desktop-debugsource-0.1.6-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-settings-daemon-3.32.0-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-settings-daemon-debuginfo-3.32.0-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-settings-daemon-debugsource-3.32.0-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-shell-3.32.2-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-shell-debuginfo-3.32.2-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-shell-debugsource-3.32.2-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-apps-menu-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-auto-move-windows-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-common-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-dash-to-dock-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-desktop-icons-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-disable-screenshield-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-drive-menu-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-horizontal-workspaces-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-launch-new-instance-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-native-window-placement-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-no-hot-corner-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-panel-favorites-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-places-menu-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-screenshot-window-sizer-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-systemMonitor-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-top-icons-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-updates-dialog-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-user-theme-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-window-grouper-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-window-list-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-windowsNavigator-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-shell-extension-workspace-indicator-3.32.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-software-3.30.6-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-software-debuginfo-3.30.6-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-software-debugsource-3.30.6-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-software-editor-3.30.6-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gnome-software-editor-debuginfo-3.30.6-2.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"gnome-tweaks-3.28.1-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gsettings-desktop-schemas-3.32.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gsettings-desktop-schemas-3.32.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gsettings-desktop-schemas-3.32.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gsettings-desktop-schemas-devel-3.32.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gsettings-desktop-schemas-devel-3.32.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk-update-icon-cache-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk-update-icon-cache-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk-update-icon-cache-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk-update-icon-cache-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk-update-icon-cache-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-debugsource-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-debugsource-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-debugsource-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-devel-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-devel-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-devel-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-devel-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-devel-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-devel-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-immodule-xim-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-immodule-xim-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-immodule-xim-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-immodule-xim-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-immodule-xim-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-immodules-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-immodules-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-immodules-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gtk3-tests-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gtk3-tests-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gtk3-tests-debuginfo-3.22.30-4.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afc-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-afc-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afc-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afp-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-afp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-afp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-afp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-archive-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-archive-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-archive-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-archive-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-client-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-client-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-client-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-client-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-client-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-client-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-debugsource-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-debugsource-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-debugsource-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-devel-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-devel-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-devel-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-fuse-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-fuse-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-fuse-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-fuse-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-fuse-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-goa-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-goa-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-goa-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-goa-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-gphoto2-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-gphoto2-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-gphoto2-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-gphoto2-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-gphoto2-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-mtp-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-mtp-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-mtp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-mtp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-mtp-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-smb-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-smb-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"gvfs-smb-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"gvfs-smb-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"gvfs-smb-debuginfo-1.36.2-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libpurple-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libpurple-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libpurple-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libpurple-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libpurple-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libpurple-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libpurple-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libpurple-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libpurple-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libpurple-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libpurple-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libpurple-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libpurple-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libpurple-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libpurple-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"libpurple-tcl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libpurple-tcl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libpurple-tcl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libpurple-tcl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mozjs60-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mozjs60-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mozjs60-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"mozjs60-debuginfo-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mozjs60-debuginfo-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mozjs60-debuginfo-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mozjs60-debuginfo-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"mozjs60-debugsource-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mozjs60-debugsource-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mozjs60-debugsource-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mozjs60-debugsource-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"mozjs60-devel-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mozjs60-devel-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"mozjs60-devel-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mozjs60-devel-60.9.0-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mutter-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mutter-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mutter-debuginfo-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mutter-debuginfo-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mutter-debugsource-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mutter-debugsource-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mutter-devel-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mutter-devel-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"mutter-tests-debuginfo-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"mutter-tests-debuginfo-3.32.2-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-debuginfo-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-debuginfo-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-debugsource-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-debugsource-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-devel-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-devel-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-extensions-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-extensions-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"nautilus-extensions-debuginfo-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"nautilus-extensions-debuginfo-3.28.1-10.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pango-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pango-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pango-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pango-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pango-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pango-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pango-debugsource-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pango-debugsource-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pango-debugsource-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pango-devel-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pango-devel-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pango-devel-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pango-tests-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pango-tests-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pango-tests-debuginfo-1.42.4-6.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pidgin-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"pidgin-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pidgin-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pidgin-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pidgin-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"pidgin-debugsource-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pidgin-debugsource-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pidgin-debugsource-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pidgin-debugsource-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pidgin-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pidgin-devel-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"pidgin-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"pidgin-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pidgin-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pidgin-perl-debuginfo-2.13.0-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-core-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-core-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-core-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-core-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-core-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-core-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-debugsource-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-debugsource-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-debugsource-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-devel-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-devel-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-devel-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-graphics-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-graphics-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-graphics-libs-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-graphics-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-graphics-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-graphics-libs-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-fade-throbber-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-fade-throbber-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-fade-throbber-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-fade-throbber-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-fade-throbber-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-label-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-label-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-label-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-label-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-label-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-script-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-script-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-script-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-script-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-script-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-space-flares-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-space-flares-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-space-flares-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-space-flares-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-space-flares-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-throbgress-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-throbgress-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-throbgress-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-throbgress-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-throbgress-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-two-step-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-two-step-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"plymouth-plugin-two-step-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-plugin-two-step-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-plugin-two-step-debuginfo-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-scripts-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-scripts-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-system-theme-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-system-theme-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-charge-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-charge-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-fade-in-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-fade-in-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-script-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-script-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-solar-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-solar-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-spinfinity-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-spinfinity-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"plymouth-theme-spinner-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"plymouth-theme-spinner-0.9.3-15.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"wayland-protocols-devel-1.17-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-debugsource-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-debugsource-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-debugsource-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-devel-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-devel-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-jsc-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-jsc-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-jsc-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-jsc-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-jsc-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-jsc-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-jsc-devel-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-jsc-devel-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-jsc-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-jsc-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-jsc-devel-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-plugin-process-gtk2-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-plugin-process-gtk2-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-plugin-process-gtk2-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.24.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"webkit2gtk3-plugin-process-gtk2-debuginfo-2.24.3-1.el8")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL / SDL-debuginfo / SDL-debugsource / SDL-devel / accountsservice / etc");
  }
}
