#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(119178);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/08");

  script_cve_id("CVE-2015-9262");

  script_name(english:"Scientific Linux Security Update : X.org X11 on SL7.x x86_64 (20181030)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - libxcursor: 1-byte heap-based overflow in
    _XcursorThemeInherits function in library.c
    (CVE-2015-9262)

The SL Team added a fix for upstream bug 1650634"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1811&L=scientific-linux-errata&F=&S=&P=1538
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eacae7ad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:egl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeglut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeglut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freeglut-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:intel-gpu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-demos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libGLES-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libwayland-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libwayland-egl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-ati-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-dummy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-evdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-evdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-evdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-fbdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-intel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mouse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-mouse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-openchrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-openchrome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-openchrome-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-qxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-synaptics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-synaptics-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-synaptics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-v4l-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vmmouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vmmouse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-vmware-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-void-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-wacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-drv-wacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-font-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xkb-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xkb-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xkb-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xkb-utils-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"drm-utils-2.4.91-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"egl-utils-8.3.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeglut-3.0.0-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeglut-debuginfo-3.0.0-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeglut-devel-3.0.0-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glx-utils-8.3.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"intel-gpu-tools-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-1.6.5-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libX11-common-1.6.5-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-debuginfo-1.6.5-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-devel-1.6.5-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-1.1.15-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-debuginfo-1.1.15-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-devel-1.1.15-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-1.5.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-debuginfo-1.5.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-devel-1.5.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-2.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-debuginfo-2.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-devel-2.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXres-1.2.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXres-debuginfo-1.2.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXres-devel-1.2.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-2.4.91-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-debuginfo-2.4.91-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-devel-2.4.91-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-debuginfo-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-devel-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-debuginfo-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-egl-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-gles-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-glx-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-1.10.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-debuginfo-1.10.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-devel-1.10.7-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-0.30-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libwacom-data-0.30-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-debuginfo-0.30-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-devel-0.30-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-1.13-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-debuginfo-1.13-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-devel-1.13-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libxcb-doc-1.13-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-debuginfo-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-demos-8.3.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-demos-debuginfo-8.3.0-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-dri-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-filesystem-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libEGL-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libEGL-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGL-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGL-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGLES-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGLES-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libOSMesa-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libOSMesa-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libgbm-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libgbm-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libglapi-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libwayland-egl-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libwayland-egl-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libxatracker-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libxatracker-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-vdpau-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-vulkan-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-icons-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-license-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-server-applet-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-module-1.8.0-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-debuginfo-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-devel-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"vulkan-filesystem-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xcb-proto-1.13-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xkeyboard-config-2.24-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xkeyboard-config-devel-2.24-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-18.0.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-ati-debuginfo-18.0.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-dummy-0.3.7-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-dummy-debuginfo-0.3.7-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-2.10.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-debuginfo-2.10.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-devel-2.10.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-fbdev-0.5.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-fbdev-debuginfo-0.5.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-debuginfo-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-0.27.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-debuginfo-0.27.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-devel-0.27.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-1.9.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-debuginfo-1.9.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-devel-1.9.2-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-nouveau-1.0.15-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-nouveau-debuginfo-1.0.15-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-0.5.0-3.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-debuginfo-0.5.0-3.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-qxl-0.1.5-4.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-qxl-debuginfo-0.1.5-4.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-1.9.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-debuginfo-1.9.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-devel-1.9.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-v4l-0.2.0-49.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-v4l-debuginfo-0.2.0-49.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-2.4.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-debuginfo-2.4.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vmmouse-13.1.0-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vmmouse-debuginfo-13.1.0-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vmware-13.2.1-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-vmware-debuginfo-13.2.1-1.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-void-1.4.1-2.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-void-debuginfo-1.4.1-2.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-0.36.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-debuginfo-0.36.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-devel-0.36.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-font-utils-7.5-21.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-font-utils-debuginfo-7.5-21.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xorg-x11-proto-devel-2018.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xspice-0.1.5-4.el7.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xwayland-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xorg-x11-server-source-1.20.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-utils-7.5-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-utils-debuginfo-7.5-23.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-xkb-extras-7.7-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-7.7-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-debuginfo-7.7-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-devel-7.7-14.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / egl-utils / freeglut / freeglut-debuginfo / etc");
}
