##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2020:1766. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145863);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2018-20337",
    "CVE-2019-3825",
    "CVE-2019-12447",
    "CVE-2019-12448",
    "CVE-2019-12449"
  );
  script_bugtraq_id(107124, 109289);
  script_xref(name:"RHSA", value:"2020:1766");

  script_name(english:"CentOS 8 : GNOME (CESA-2020:1766)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:1766 advisory.

  - LibRaw: stack-based buffer overflow in the parse_makernote function of dcraw_common.cpp (CVE-2018-20337)

  - gvfs: mishandling of file ownership in daemon/gvfsbackendadmin.c (CVE-2019-12447)

  - gvfs: race condition in daemon/gvfsbackendadmin.c due to admin backend not implementing
    query_info_on_read/write (CVE-2019-12448)

  - gvfs: mishandling of file's user and group ownership in daemon/gvfsbackendadmin.c due to unavailability of
    root privileges (CVE-2019-12449)

  - gdm: lock screen bypass when timed login is enabled (CVE-2019-3825)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1766");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3825");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:baobab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-menus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-menus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-terminal-nautilus");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvncserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs52-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozjs60-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vala-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vinagre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'appstream-data-8-20191129.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'appstream-data-8-20191129.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'baobab-3.28.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'baobab-3.28.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-devel-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-devel-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-doc-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-doc-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-libs-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gdm-3.28.3-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gdm-3.28.3-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'gjs-1.56.2-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-1.56.2-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gjs-devel-1.56.2-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-boxes-3.28.5-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-boxes-3.28.5-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-tweaks-3.28.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-tweaks-3.28.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-devel-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afc-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-afp-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-archive-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-client-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-devel-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-fuse-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-goa-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-gphoto2-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-mtp-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-8.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gvfs-smb-1.36.2-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvncserver-0.9.11-14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvncserver-0.9.11-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvncserver-devel-0.9.11-14.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libvncserver-devel-0.9.11-14.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxslt-1.1.32-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxslt-1.1.32-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxslt-devel-1.1.32-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxslt-devel-1.1.32-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs52-52.9.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs52-52.9.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs52-devel-52.9.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs52-devel-52.9.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-60.9.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-60.9.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-devel-60.9.0-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mozjs60-devel-60.9.0-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-34.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-0.40.19-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-0.40.19-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-devel-0.40.19-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vala-devel-0.40.19-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vinagre-3.22.0-21.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vinagre-3.22.0-21.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / accountsservice / accountsservice-devel / etc');
}
