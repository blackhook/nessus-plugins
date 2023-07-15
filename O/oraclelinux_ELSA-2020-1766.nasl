#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-1766.
#

include('compat.inc');

if (description)
{
  script_id(140034);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2018-20337",
    "CVE-2019-3825",
    "CVE-2019-12447",
    "CVE-2019-12448",
    "CVE-2019-12449"
  );
  script_bugtraq_id(107124, 109289);

  script_name(english:"Oracle Linux 8 : GNOME (ELSA-2020-1766)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-1766 advisory.

  - There is a stack-based buffer overflow in the parse_makernote function of dcraw_common.cpp in LibRaw
    0.19.1. Crafted input will lead to a denial of service or possibly unspecified other impact.
    (CVE-2018-20337)

  - A vulnerability was discovered in gdm before 3.31.4. When timed login is enabled in configuration, an
    attacker could bypass the lock screen by selecting the timed login user and waiting for the timer to
    expire, at which time they would gain access to the logged-in user's session. (CVE-2019-3825)

  - An issue was discovered in GNOME gvfs 1.29.4 through 1.41.2. daemon/gvfsbackendadmin.c mishandles file
    ownership because setfsuid is not used. (CVE-2019-12447)

  - An issue was discovered in GNOME gvfs 1.29.4 through 1.41.2. daemon/gvfsbackendadmin.c has race conditions
    because the admin backend doesn't implement query_info_on_read/write. (CVE-2019-12448)

  - An issue was discovered in GNOME gvfs 1.29.4 through 1.41.2. daemon/gvfsbackendadmin.c mishandles a file's
    user and group ownership during move (and copy with G_FILE_COPY_ALL_METADATA) operations from admin:// to
    file:// URIs, because root privileges are unavailable. (CVE-2019-12449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://linux.oracle.com/errata/ELSA-2020-1766.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:LibRaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:LibRaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:accountsservice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:appstream-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gjs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-boxes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-menus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-menus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-online-accounts-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-remote-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session-wayland-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-software");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-software-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-terminal-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-tweaks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gsettings-desktop-schemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gsettings-desktop-schemas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-update-icon-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk3-immodule-xim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvncserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mozjs52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mozjs52-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mozjs60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mozjs60-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nautilus-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vala-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:vinagre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'accountsservice-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'accountsservice-devel-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'accountsservice-libs-0.6.50-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'appstream-data-8-20191129.el8', 'release':'8'},
    {'reference':'clutter-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'clutter-1.26.2-8.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'clutter-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'clutter-devel-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'clutter-devel-1.26.2-8.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'clutter-devel-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'clutter-doc-1.26.2-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'clutter-doc-1.26.2-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'evince-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'evince-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'evince-browser-plugin-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'evince-libs-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'evince-libs-3.28.4-4.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'evince-libs-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'evince-nautilus-3.28.4-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gdm-3.28.3-29.el8', 'cpu':'aarch64', 'release':'8', 'epoch':'1'},
    {'reference':'gdm-3.28.3-29.el8', 'cpu':'i686', 'release':'8', 'epoch':'1'},
    {'reference':'gdm-3.28.3-29.el8', 'cpu':'x86_64', 'release':'8', 'epoch':'1'},
    {'reference':'gjs-1.56.2-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gjs-1.56.2-4.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gjs-1.56.2-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gjs-devel-1.56.2-4.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gjs-devel-1.56.2-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-boxes-3.28.5-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-control-center-3.28.2-19.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-control-center-filesystem-3.28.2-19.el8', 'release':'8'},
    {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gnome-menus-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gnome-menus-devel-3.13.3-11.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gnome-online-accounts-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gnome-online-accounts-devel-3.28.2-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-remote-desktop-0.1.6-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-wayland-session-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-session-xsession-3.28.1-8.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-settings-daemon-3.32.0-9.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-shell-3.32.2-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-software-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-software-editor-3.30.6-3.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-terminal-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gnome-terminal-nautilus-3.28.3-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gnome-tweaks-3.28.1-7.el8', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gsettings-desktop-schemas-devel-3.32.0-4.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk-update-icon-cache-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-3.22.30-5.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gtk3-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-5.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'gtk3-devel-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'gtk3-immodule-xim-3.22.30-5.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'LibRaw-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'LibRaw-devel-0.19.5-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libvncserver-0.9.11-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libvncserver-0.9.11-14.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libvncserver-0.9.11-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libvncserver-devel-0.9.11-14.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libvncserver-devel-0.9.11-14.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libvncserver-devel-0.9.11-14.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libxslt-1.1.32-4.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libxslt-1.1.32-4.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libxslt-1.1.32-4.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libxslt-devel-1.1.32-4.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libxslt-devel-1.1.32-4.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libxslt-devel-1.1.32-4.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mozjs52-52.9.0-2.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mozjs52-52.9.0-2.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mozjs52-52.9.0-2.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mozjs52-devel-52.9.0-2.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mozjs52-devel-52.9.0-2.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mozjs52-devel-52.9.0-2.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mozjs60-60.9.0-4.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mozjs60-60.9.0-4.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mozjs60-60.9.0-4.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mozjs60-devel-60.9.0-4.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mozjs60-devel-60.9.0-4.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mozjs60-devel-60.9.0-4.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mutter-3.32.2-34.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'mutter-3.32.2-34.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mutter-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'mutter-devel-3.32.2-34.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nautilus-3.28.1-12.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-devel-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nautilus-extensions-3.28.1-12.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vala-0.40.19-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vala-0.40.19-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'vala-0.40.19-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vala-devel-0.40.19-1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vala-devel-0.40.19-1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'vala-devel-0.40.19-1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'vinagre-3.22.0-21.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'vinagre-3.22.0-21.el8', 'cpu':'x86_64', 'release':'8'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibRaw / LibRaw-devel / accountsservice / etc');
}
