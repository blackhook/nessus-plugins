#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1865. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102147);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-10164", "CVE-2017-2625", "CVE-2017-2626");
  script_xref(name:"RHSA", value:"2017:1865");

  script_name(english:"RHEL 7 : X.org X11 libraries (RHSA-2017:1865)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2626"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libICE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libICE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libICE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXdmcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXdmcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXdmcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libevdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libevdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libevdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libevdev-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfontenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfontenc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfontenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvdpau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvdpau-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvdpau-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbfile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxkbfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-private-llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-private-llvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-private-llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1865";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"drm-utils-2.4.74-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"drm-utils-2.4.74-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libICE-1.0.9-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libICE-debuginfo-1.0.9-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libICE-devel-1.0.9-9.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libX11-1.6.5-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libX11-common-1.6.5-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libX11-debuginfo-1.6.5-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libX11-devel-1.6.5-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXaw-1.0.13-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXaw-debuginfo-1.0.13-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXaw-devel-1.0.13-4.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXcursor-1.1.14-8.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXcursor-debuginfo-1.1.14-8.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXcursor-devel-1.1.14-8.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXdmcp-1.1.2-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXdmcp-debuginfo-1.1.2-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXdmcp-devel-1.1.2-6.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfixes-5.0.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfixes-debuginfo-5.0.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfixes-devel-5.0.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont-1.5.2-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont-debuginfo-1.5.2-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont-devel-1.5.2-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont2-2.0.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont2-debuginfo-2.0.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXfont2-devel-2.0.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXi-1.7.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXi-debuginfo-1.7.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXi-devel-1.7.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXpm-3.5.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXpm-debuginfo-3.5.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXpm-devel-3.5.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrandr-1.5.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrandr-debuginfo-1.5.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrandr-devel-1.5.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrender-0.9.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrender-debuginfo-0.9.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXrender-devel-0.9.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXt-1.1.5-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXt-debuginfo-1.1.5-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXt-devel-1.1.5-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXtst-1.2.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXtst-debuginfo-1.2.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXtst-devel-1.2.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXv-1.0.11-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXv-debuginfo-1.0.11-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXv-devel-1.0.11-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libXvMC-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libXvMC-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libXvMC-debuginfo-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libXvMC-debuginfo-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libXvMC-devel-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libXvMC-devel-1.0.10-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXxf86vm-1.1.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXxf86vm-debuginfo-1.1.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libXxf86vm-devel-1.1.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libdrm-2.4.74-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libdrm-debuginfo-2.4.74-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libdrm-devel-2.4.74-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libepoxy-1.3.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libepoxy-debuginfo-1.3.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libepoxy-devel-1.3.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libevdev-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libevdev-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libevdev-debuginfo-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libevdev-debuginfo-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libevdev-devel-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libevdev-devel-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libevdev-utils-1.5.6-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libfontenc-1.1.3-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libfontenc-debuginfo-1.1.3-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libfontenc-devel-1.1.3-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-debuginfo-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-debuginfo-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libinput-devel-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libinput-devel-1.6.3-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libvdpau-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvdpau-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libvdpau-debuginfo-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvdpau-debuginfo-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libvdpau-devel-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvdpau-devel-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libvdpau-docs-1.1.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwacom-0.24-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwacom-data-0.24-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwacom-debuginfo-0.24-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libwacom-devel-0.24-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxcb-1.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxcb-debuginfo-1.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxcb-devel-1.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxcb-doc-1.12-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-0.7.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-debuginfo-0.7.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-devel-0.7.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-x11-0.7.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbcommon-x11-devel-0.7.1-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbfile-1.0.9-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbfile-debuginfo-1.0.9-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libxkbfile-devel-1.0.9-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-debuginfo-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-dri-drivers-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-filesystem-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libEGL-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libEGL-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libGL-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libGL-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libGLES-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libGLES-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libOSMesa-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libOSMesa-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libgbm-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libgbm-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"mesa-libglapi-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-libxatracker-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-libxatracker-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-libxatracker-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-libxatracker-devel-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-private-llvm-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mesa-private-llvm-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-private-llvm-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-private-llvm-debuginfo-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mesa-private-llvm-debuginfo-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-private-llvm-debuginfo-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"mesa-private-llvm-devel-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mesa-private-llvm-devel-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-private-llvm-devel-3.9.1-3.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mesa-vulkan-drivers-17.0.1-6.20170307.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-debuginfo-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-debuginfo-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"vulkan-devel-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vulkan-devel-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"vulkan-filesystem-1.0.39.1-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xcb-proto-1.12-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xkeyboard-config-2.20-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xkeyboard-config-devel-2.20-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xorg-x11-proto-devel-7.7-20.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / libICE / libICE-debuginfo / libICE-devel / libX11 / etc");
  }
}
