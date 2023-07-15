#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(135796);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2019-3820");

  script_name(english:"Scientific Linux Security Update : GNOME on SL7.x x86_64 (20200407)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:"* gnome-shell: partial lock screen bypass"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2004&L=SCIENTIFIC-LINUX-ERRATA&P=9130
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1df466fb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:LibRaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:LibRaw-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:accountsservice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord-extra-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:colord-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gdm-pam-extensions-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-online-accounts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-settings-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-settings-daemon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-alternate-tab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-disable-screenshield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-extra-osk-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-horizontal-workspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-no-hot-corner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-window-grouper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-tweak-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-immodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk3-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcanberra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcanberra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcanberra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcanberra-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcanberra-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgweather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgweather-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgweather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mutter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:osinfo-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:shared-mime-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:shared-mime-info-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker-needle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tracker-preferences");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xchat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xchat-tcl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"LibRaw-0.19.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"LibRaw-debuginfo-0.19.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"LibRaw-devel-0.19.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"LibRaw-static-0.19.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"accountsservice-0.6.50-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"accountsservice-debuginfo-0.6.50-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"accountsservice-devel-0.6.50-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"accountsservice-libs-0.6.50-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"colord-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"colord-debuginfo-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"colord-devel-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"colord-devel-docs-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"colord-extra-profiles-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"colord-libs-1.3.4-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"control-center-3.28.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"control-center-debuginfo-3.28.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"control-center-filesystem-3.28.1-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gdm-3.28.2-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gdm-debuginfo-3.28.2-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gdm-devel-3.28.2-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gdm-pam-extensions-devel-3.28.2-22.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-classic-session-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-classic-session-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-online-accounts-3.28.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-online-accounts-debuginfo-3.28.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-online-accounts-devel-3.28.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-settings-daemon-3.28.1-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-settings-daemon-debuginfo-3.28.1-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-settings-daemon-devel-3.28.1-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-3.28.3-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-debuginfo-3.28.3-24.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-alternate-tab-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-alternate-tab-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-apps-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-apps-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-auto-move-windows-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-common-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-common-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-dash-to-dock-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-disable-screenshield-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-drive-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-extra-osk-keys-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-horizontal-workspaces-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-horizontal-workspaces-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-launch-new-instance-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-launch-new-instance-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-native-window-placement-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-no-hot-corner-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-panel-favorites-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-places-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-places-menu-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-screenshot-window-sizer-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-systemMonitor-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-top-icons-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-top-icons-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-updates-dialog-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-user-theme-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-user-theme-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-window-grouper-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-window-list-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-shell-extension-window-list-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-windowsNavigator-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-shell-extension-workspace-indicator-3.28.1-11.el7")) flag++;
if (rpm_check(release:"SL7", reference:"gnome-tweak-tool-3.28.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gnome-tweak-tool-3.28.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gsettings-desktop-schemas-3.28.0-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gsettings-desktop-schemas-devel-3.28.0-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-update-icon-cache-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-debuginfo-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-devel-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-devel-docs-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-immodule-xim-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-immodules-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk3-tests-3.22.30-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcanberra-0.30-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcanberra-debuginfo-0.30-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcanberra-devel-0.30-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcanberra-gtk2-0.30-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcanberra-gtk3-0.30-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgweather-3.28.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgweather-debuginfo-3.28.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgweather-devel-3.28.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-3.28.3-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-debuginfo-3.28.3-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mutter-devel-3.28.3-20.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nautilus-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nautilus-debuginfo-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nautilus-devel-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nautilus-extensions-3.26.3.1-7.el7")) flag++;
if (rpm_check(release:"SL7", reference:"osinfo-db-20190805-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"osinfo-db-20190805-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"shared-mime-info-1.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"shared-mime-info-debuginfo-1.8-5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tracker-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tracker-debuginfo-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tracker-devel-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tracker-docs-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tracker-needle-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tracker-preferences-1.10.5-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xchat-2.8.8-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xchat-debuginfo-2.8.8-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xchat-tcl-2.8.8-25.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibRaw / LibRaw-debuginfo / LibRaw-devel / LibRaw-static / etc");
}
