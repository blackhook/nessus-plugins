#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3059 and 
# CentOS Errata and Security Advisory 2018:3059 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118986);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id("CVE-2015-9262");
  script_xref(name:"RHSA", value:"2018:3059");

  script_name(english:"CentOS 7 : freeglut / libX11 / libXcursor / libXfont / libXfont2 / libXres / libdrm / libepoxy / etc (CESA-2018:3059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
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
Enterprise Linux 7.6 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005388.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e5c55f8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82823c66"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?359a64cc"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6654196"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93908f20"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9feeb980"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?404004a3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2836993b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c59b57c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?845593f5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d64da736"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?091da502"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0761ed12"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ec861a5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005673.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49c10748"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5a94fd7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74ad4d86"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d796de90"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?809c2ce1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbece2e4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05a7a85d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?893225a6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005717.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ae3e33e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55273d0d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3e6aff9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04fa008a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?709789fe"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57d12d87"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46c049cf"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3067351b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c0b7150"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70491862"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f0ae85b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9534a0d8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a54b003"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef342f2d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2ee7ee8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c5f5fea"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06c57d0b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2018-November/005734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?620f5e82"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9262");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:egl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeglut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeglut-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:intel-gpu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGLES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libGLES-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libOSMesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libwayland-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libwayland-egl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-evdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-evdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-intel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-mouse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-openchrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-openchrome-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-synaptics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-synaptics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-vmmouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-drv-wacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xspice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xkb-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xkb-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xkb-utils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"drm-utils-2.4.91-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"egl-utils-8.3.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"freeglut-3.0.0-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"freeglut-devel-3.0.0-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"glx-utils-8.3.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"intel-gpu-tools-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-1.6.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-common-1.6.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-devel-1.6.5-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXcursor-1.1.15-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXcursor-devel-1.1.15-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-1.5.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-devel-1.5.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont2-2.0.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont2-devel-2.0.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXres-1.2.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXres-devel-1.2.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libdrm-2.4.91-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libdrm-devel-2.4.91-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libepoxy-1.5.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libepoxy-devel-1.5.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-core-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-devel-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-egl-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-gles-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-glx-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libglvnd-opengl-1.0.1-0.8.git5baa1e5.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libinput-1.10.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libinput-devel-1.10.7-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-0.30-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-data-0.30-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-devel-0.30-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-1.13-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-devel-1.13-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-doc-1.13-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-demos-8.3.0-10.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-dri-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-filesystem-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libEGL-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libEGL-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGL-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGL-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGLES-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGLES-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libOSMesa-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libOSMesa-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libgbm-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libgbm-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libglapi-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libwayland-egl-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libwayland-egl-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libxatracker-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libxatracker-devel-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-vdpau-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-vulkan-drivers-18.0.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-icons-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-license-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-applet-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"tigervnc-server-module-1.8.0-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-devel-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-filesystem-1.1.73.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xcb-proto-1.13-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xkeyboard-config-2.24-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xkeyboard-config-devel-2.24-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-ati-18.0.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-dummy-0.3.7-1.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-2.10.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-evdev-devel-2.10.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-fbdev-0.5.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-intel-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-intel-devel-2.99.917-28.20180530.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-0.27.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-libinput-devel-0.27.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-1.9.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-mouse-devel-1.9.2-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-nouveau-1.0.15-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-0.5.0-3.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-openchrome-devel-0.5.0-3.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-qxl-0.1.5-4.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-1.9.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-synaptics-devel-1.9.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-v4l-0.2.0-49.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-vesa-2.4.0-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-vmmouse-13.1.0-1.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-vmware-13.2.1-1.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-void-1.4.1-2.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-0.36.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-drv-wacom-devel-0.36.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-font-utils-7.5-21.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-proto-devel-2018.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xspice-0.1.5-4.el7.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xwayland-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-common-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-source-1.20.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-utils-7.5-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-xkb-extras-7.7-14.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-7.7-14.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-xkb-utils-devel-7.7-14.el7")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / egl-utils / freeglut / freeglut-devel / glx-utils / etc");
}
