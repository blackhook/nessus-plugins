#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1021 and 
# CentOS Errata and Security Advisory 2020:1021 respectively.
#

include("compat.inc");

if (description)
{
  script_id(135318);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2019-3820");
  script_xref(name:"RHSA", value:"2020:1021");

  script_name(english:"CentOS 7 : LibRaw / accountsservice / colord / control-center / gdm / gnome-online-accounts / etc (CESA-2020:1021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:1021 advisory.

  - gnome-shell: partial lock screen bypass (CVE-2019-3820)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a5dccaa"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca314f22"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21155e61"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012450.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9972031d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012454.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fbed5df"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012455.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde820dc"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0fc45b5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8b1a803"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f433158"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6908d95"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2b7db3d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012493.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75b6eccc"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?041868ac"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d4bae82"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b5b3f9b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9606a79e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84061919"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4305f97"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48fd8a0e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ff32944"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3820");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:colord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:colord-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:colord-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:colord-extra-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:colord-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-pam-extensions-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-settings-daemon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-alternate-tab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell-extension-extra-osk-keys");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-tweak-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-immodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcanberra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcanberra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcanberra-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcanberra-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgweather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:osinfo-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shared-mime-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tracker-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tracker-needle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tracker-preferences");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xchat-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"LibRaw-0.19.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"LibRaw-devel-0.19.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"LibRaw-static-0.19.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-0.6.50-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-devel-0.6.50-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"accountsservice-libs-0.6.50-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"colord-1.3.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"colord-devel-1.3.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"colord-devel-docs-1.3.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"colord-extra-profiles-1.3.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"colord-libs-1.3.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"control-center-3.28.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"control-center-filesystem-3.28.1-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-3.28.2-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-devel-3.28.2-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-pam-extensions-devel-3.28.2-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-classic-session-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-online-accounts-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-online-accounts-devel-3.28.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-settings-daemon-3.28.1-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-settings-daemon-devel-3.28.1-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-3.28.3-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-alternate-tab-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-apps-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-auto-move-windows-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-common-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-dash-to-dock-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-disable-screenshield-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-drive-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-extra-osk-keys-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-horizontal-workspaces-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-launch-new-instance-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-native-window-placement-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-no-hot-corner-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-panel-favorites-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-places-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-screenshot-window-sizer-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-systemMonitor-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-top-icons-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-updates-dialog-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-user-theme-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-window-grouper-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-window-list-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-windowsNavigator-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-shell-extension-workspace-indicator-3.28.1-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-tweak-tool-3.28.1-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gsettings-desktop-schemas-3.28.0-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gsettings-desktop-schemas-devel-3.28.0-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk-update-icon-cache-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-devel-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-devel-docs-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-immodule-xim-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-immodules-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gtk3-tests-3.22.30-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcanberra-0.30-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcanberra-devel-0.30-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcanberra-gtk2-0.30-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcanberra-gtk3-0.30-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgweather-3.28.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgweather-devel-3.28.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mutter-3.28.3-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mutter-devel-3.28.3-20.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-devel-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nautilus-extensions-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"osinfo-db-20190805-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"shared-mime-info-1.8-5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tracker-1.10.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tracker-devel-1.10.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tracker-docs-1.10.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tracker-needle-1.10.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tracker-preferences-1.10.5-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xchat-2.8.8-25.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xchat-tcl-2.8.8-25.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibRaw / LibRaw-devel / LibRaw-static / accountsservice / etc");
}
