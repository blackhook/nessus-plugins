#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1865 and 
# CentOS Errata and Security Advisory 2017:1865 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102740);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10164", "CVE-2017-2625", "CVE-2017-2626");
  script_xref(name:"RHSA", value:"2017:1865");

  script_name(english:"CentOS 7 : libICE / libX11 / libXaw / libXcursor / libXdmcp / libXfixes / libXfont / libXfont2 / etc (CESA-2017:1865)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The X11 (Xorg) libraries provide library routines that are used within
all X Window applications.

The following packages have been upgraded to a later upstream version:
libX11 (1.6.5), libXaw (1.0.13), libXdmcp (1.1.2), libXfixes (5.0.3),
libXfont (1.5.2), libXi (1.7.9), libXpm (3.5.12), libXrandr (1.5.1),
libXrender (0.9.10), libXt (1.1.5), libXtst (1.2.3), libXv (1.0.11),
libXvMC (1.0.10), libXxf86vm (1.1.4), libdrm (2.4.74), libepoxy
(1.3.1), libevdev (1.5.6), libfontenc (1.1.3), libvdpau (1.1.1),
libwacom (0.24), libxcb (1.12), libxkbfile (1.0.9), mesa (17.0.1),
mesa-private-llvm (3.9.1), xcb-proto (1.12), xkeyboard-config (2.20),
xorg-x11-proto-devel (7.7). (BZ#1401667, BZ#1401668, BZ#1401669,
BZ#1401670, BZ#1401671, BZ#1401672, BZ#1401673, BZ#1401675, BZ#
1401676, BZ#1401677, BZ#1401678, BZ#1401679, BZ#1401680, BZ#1401681,
BZ# 1401682, BZ#1401683, BZ#1401685, BZ#1401690, BZ#1401752,
BZ#1401753, BZ# 1401754, BZ#1402560, BZ#1410477, BZ#1411390,
BZ#1411392, BZ#1411393, BZ# 1411452, BZ#1420224)

Security Fix(es) :

* An integer overflow flaw leading to a heap-based buffer overflow was
found in libXpm. An attacker could use this flaw to crash an
application using libXpm via a specially crafted XPM file.
(CVE-2016-10164)

* It was discovered that libXdmcp used weak entropy to generate
session keys. On a multi-user system using xdmcp, a local attacker
could potentially use information available from the process list to
brute force the key, allowing them to hijack other users' sessions.
(CVE-2017-2625)

* It was discovered that libICE used a weak entropy to generate keys.
A local attacker could potentially use this flaw for session hijacking
using the information available from the process list. (CVE-2017-2626)

Red Hat would like to thank Eric Sesterhenn (X41 D-Sec GmbH) for
reporting CVE-2017-2625 and CVE-2017-2626.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?166c5e9c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ef14f4c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b9095bf"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be206971"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42dd0d2a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d1c2f35"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55e439ae"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f831a43"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f15140e2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc328e96"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc6807e2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6649d2ce"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fed46cd4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6ad6a04"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3920b485"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e5332b3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d283952"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004345.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d66f7d3a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c95ed42"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?176b1b32"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a6bf037"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c45f4b56"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff41a9ad"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f895ff1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11c36ee0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?202286cf"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8751d95f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79e32cf4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2822f355"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b07ca9a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2c20b15"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?002a40e0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?809e61ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10164");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libICE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libICE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXdmcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXdmcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libevdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libevdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libevdev-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libfontenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libfontenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvdpau-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvdpau-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbcommon-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxkbfile-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-private-llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-private-llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vdpau-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"drm-utils-2.4.74-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libICE-1.0.9-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libICE-devel-1.0.9-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-1.6.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-common-1.6.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libX11-devel-1.6.5-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXaw-1.0.13-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXaw-devel-1.0.13-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXcursor-1.1.14-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXcursor-devel-1.1.14-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXdmcp-1.1.2-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXdmcp-devel-1.1.2-6.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfixes-5.0.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfixes-devel-5.0.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-1.5.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-devel-1.5.2-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont2-2.0.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont2-devel-2.0.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXi-1.7.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXi-devel-1.7.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXpm-3.5.12-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXpm-devel-3.5.12-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXrandr-1.5.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXrandr-devel-1.5.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXrender-0.9.10-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXrender-devel-0.9.10-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXt-1.1.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXt-devel-1.1.5-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXtst-1.2.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXtst-devel-1.2.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXv-1.0.11-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXv-devel-1.0.11-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXvMC-1.0.10-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXvMC-devel-1.0.10-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXxf86vm-1.1.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXxf86vm-devel-1.1.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libdrm-2.4.74-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libdrm-devel-2.4.74-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libepoxy-1.3.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libepoxy-devel-1.3.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libevdev-1.5.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libevdev-devel-1.5.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libevdev-utils-1.5.6-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libfontenc-1.1.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libfontenc-devel-1.1.3-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libinput-1.6.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libinput-devel-1.6.3-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvdpau-1.1.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvdpau-devel-1.1.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvdpau-docs-1.1.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-0.24-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-data-0.24-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libwacom-devel-0.24-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-1.12-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-devel-1.12-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxcb-doc-1.12-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbcommon-0.7.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbcommon-devel-0.7.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbcommon-x11-0.7.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbcommon-x11-devel-0.7.1-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbfile-1.0.9-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxkbfile-devel-1.0.9-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-dri-drivers-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-filesystem-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libEGL-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libEGL-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGL-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGL-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGLES-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libGLES-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libOSMesa-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libOSMesa-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libgbm-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libgbm-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libglapi-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libxatracker-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-libxatracker-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-private-llvm-3.9.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-private-llvm-devel-3.9.1-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-vdpau-drivers-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mesa-vulkan-drivers-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-devel-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"vulkan-filesystem-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xcb-proto-1.12-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xkeyboard-config-2.20-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xkeyboard-config-devel-2.20-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-proto-devel-7.7-20.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / libICE / libICE-devel / libX11 / libX11-common / etc");
}
