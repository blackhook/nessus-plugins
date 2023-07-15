#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3059. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118520);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2015-9262");
  script_xref(name:"RHSA", value:"2018:3059");

  script_name(english:"RHEL 7 : X.org X11 (RHSA-2018:3059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated X.org server and driver packages are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Security Fix(es) :

* libxcursor: 1-byte heap-based overflow in _XcursorThemeInherits
function in library.c (CVE-2015-9262)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3395ff0b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3059");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-9262");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9262");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:egl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeglut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeglut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeglut-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:intel-gpu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-demos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libGLES-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libwayland-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libwayland-egl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-ati-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-dummy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-evdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-evdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-evdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-fbdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-intel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-mouse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-mouse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-openchrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-openchrome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-openchrome-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-qxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-synaptics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-synaptics-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-synaptics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-v4l-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vmmouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vmmouse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-vmware-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-void-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-drv-wacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-font-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xkb-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xkb-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xkb-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xkb-utils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3059";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"drm-utils-2.4.91-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"drm-utils-2.4.91-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"egl-utils-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"egl-utils-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"freeglut-3.0.0-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"freeglut-debuginfo-3.0.0-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"freeglut-devel-3.0.0-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"glx-utils-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"glx-utils-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"intel-gpu-tools-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-1.6.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-common-1.6.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-debuginfo-1.6.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libX11-devel-1.6.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXcursor-1.1.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXcursor-debuginfo-1.1.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXcursor-devel-1.1.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont-1.5.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont-debuginfo-1.5.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont-devel-1.5.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont2-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont2-debuginfo-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXfont2-devel-2.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXres-1.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXres-debuginfo-1.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libXres-devel-1.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libdrm-2.4.91-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libdrm-debuginfo-2.4.91-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libdrm-devel-2.4.91-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libepoxy-1.5.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libepoxy-debuginfo-1.5.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libepoxy-devel-1.5.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-debuginfo-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-egl-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-gles-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-glx-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-debuginfo-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-debuginfo-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-devel-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-devel-1.10.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwacom-0.30-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwacom-data-0.30-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwacom-debuginfo-0.30-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libwacom-devel-0.30-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxcb-1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxcb-debuginfo-1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxcb-devel-1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libxcb-doc-1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-debuginfo-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mesa-demos-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-demos-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mesa-demos-debuginfo-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-demos-debuginfo-8.3.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-dri-drivers-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-filesystem-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libEGL-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libEGL-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGL-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGL-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGLES-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libGLES-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libOSMesa-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libOSMesa-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libgbm-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libgbm-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libglapi-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libwayland-egl-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mesa-libwayland-egl-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-libxatracker-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-libxatracker-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-libxatracker-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-libxatracker-devel-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-vdpau-drivers-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-vdpau-drivers-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-vulkan-drivers-18.0.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-debuginfo-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tigervnc-icons-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tigervnc-license-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-server-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tigervnc-server-applet-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tigervnc-server-minimal-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tigervnc-server-module-1.8.0-13.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-debuginfo-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-debuginfo-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-devel-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-devel-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"vulkan-filesystem-1.1.73.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xcb-proto-1.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xkeyboard-config-2.24-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xkeyboard-config-devel-2.24-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-18.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-debuginfo-18.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-dummy-0.3.7-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-dummy-debuginfo-0.3.7-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-2.10.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-evdev-debuginfo-2.10.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-debuginfo-2.10.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-evdev-devel-2.10.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-devel-2.10.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-fbdev-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-fbdev-debuginfo-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-intel-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-intel-debuginfo-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-debuginfo-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-0.27.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-libinput-debuginfo-0.27.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-debuginfo-0.27.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-libinput-devel-0.27.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-devel-0.27.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-1.9.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-mouse-debuginfo-1.9.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-debuginfo-1.9.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-mouse-devel-1.9.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-devel-1.9.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-nouveau-1.0.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-nouveau-debuginfo-1.0.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-openchrome-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-openchrome-debuginfo-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-debuginfo-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-qxl-0.1.5-4.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-qxl-debuginfo-0.1.5-4.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-1.9.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-synaptics-debuginfo-1.9.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-debuginfo-1.9.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-synaptics-devel-1.9.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-devel-1.9.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-v4l-0.2.0-49.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-v4l-debuginfo-0.2.0-49.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-debuginfo-2.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vmmouse-13.1.0-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vmmouse-debuginfo-13.1.0-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vmware-13.2.1-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-vmware-debuginfo-13.2.1-1.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-void-1.4.1-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-void-debuginfo-1.4.1-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-0.36.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-wacom-debuginfo-0.36.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-debuginfo-0.36.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-drv-wacom-devel-0.36.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-devel-0.36.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-font-utils-7.5-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-font-utils-7.5-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-font-utils-debuginfo-7.5-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-font-utils-debuginfo-7.5-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xorg-x11-proto-devel-2018.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xdmx-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xspice-0.1.5-4.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xwayland-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xwayland-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-common-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-debuginfo-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-debuginfo-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-devel-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xorg-x11-server-source-1.20.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-utils-7.5-23.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-utils-7.5-23.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-utils-debuginfo-7.5-23.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-utils-debuginfo-7.5-23.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-xkb-extras-7.7-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-xkb-extras-7.7-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-xkb-utils-7.7-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-7.7-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xorg-x11-xkb-utils-debuginfo-7.7-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"xorg-x11-xkb-utils-devel-7.7-14.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / egl-utils / freeglut / freeglut-debuginfo / etc");
  }
}
