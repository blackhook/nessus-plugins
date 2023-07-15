#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:1804. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149765);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id(
    "CVE-2020-14344",
    "CVE-2020-14345",
    "CVE-2020-14346",
    "CVE-2020-14347",
    "CVE-2020-14360",
    "CVE-2020-14361",
    "CVE-2020-14362",
    "CVE-2020-14363",
    "CVE-2020-25712"
  );
  script_xref(name:"RHSA", value:"2021:1804");

  script_name(english:"CentOS 8 : userspace graphics, xorg-x11, and mesa (CESA-2021:1804)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:1804 advisory.

  - libX11: Heap overflow in the X input method client (CVE-2020-14344)

  - xorg-x11-server: Out-of-bounds access in XkbSetNames function (CVE-2020-14345)

  - xorg-x11-server: Integer underflow in the X input extension protocol (CVE-2020-14346)

  - xorg-x11-server: Leak of uninitialized heap memory from the X server to clients in AllocatePixmap of
    dix/pixmap.c (CVE-2020-14347)

  - xorg-x11-server: Out-of-bounds access in XkbSetMap function (CVE-2020-14360)

  - xorg-x11-server: XkbSelectEvents integer underflow privilege escalation vulnerability (CVE-2020-14361)

  - xorg-x11-server: XRecordRegisterClients integer underflow privilege escalation vulnerability
    (CVE-2020-14362)

  - libX11: integer overflow leads to double free in locale handling (CVE-2020-14363)

  - xorg-x11-server: XkbSetDeviceInfo heap-based buffer overflow privilege escalation vulnerability
    (CVE-2020-25712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1804");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:egl-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-xcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'egl-wayland-1.1.5-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'egl-wayland-1.1.5-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-2.4.103-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-2.4.103-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-devel-2.4.103-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdrm-devel-2.4.103-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-core-devel-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-core-devel-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-devel-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-devel-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-egl-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-egl-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-gles-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-gles-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-glx-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-glx-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-opengl-1.3.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libglvnd-opengl-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-1.16.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-1.16.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.16.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.16.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-utils-1.16.3-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-utils-1.16.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-1.6-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-1.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-data-1.6-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-data-1.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-1.6-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-1.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-1.6.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-1.6.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-common-1.6.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-common-1.6.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-devel-1.6.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-devel-1.6.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-xcb-1.6.8-4.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libX11-xcb-1.6.8-4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-dri-drivers-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-dri-drivers-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-filesystem-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-filesystem-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-devel-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libEGL-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-devel-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libGL-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libglapi-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libglapi-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libxatracker-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vdpau-drivers-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vdpau-drivers-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-devel-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-drivers-20.3.3-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-vulkan-drivers-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drivers-7.7-30.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drivers-7.7-30.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-common-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.10-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'egl-wayland / libX11 / libX11-common / libX11-devel / libX11-xcb / etc');
}
