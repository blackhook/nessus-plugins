#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102636);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-10164", "CVE-2017-2625", "CVE-2017-2626");

  script_name(english:"Scientific Linux Security Update : X.org X11 libraries on SL7.x x86_64 (20170801)");
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
"The following packages have been upgraded to a later upstream version:
libX11 (1.6.5), libXaw (1.0.13), libXdmcp (1.1.2), libXfixes (5.0.3),
libXfont (1.5.2), libXi (1.7.9), libXpm (3.5.12), libXrandr (1.5.1),
libXrender (0.9.10), libXt (1.1.5), libXtst (1.2.3), libXv (1.0.11),
libXvMC (1.0.10), libXxf86vm (1.1.4), libdrm (2.4.74), libepoxy
(1.3.1), libevdev (1.5.6), libfontenc (1.1.3), libvdpau (1.1.1),
libwacom (0.24), libxcb (1.12), libxkbfile (1.0.9), mesa (17.0.1),
mesa-private-llvm (3.9.1), xcb-proto (1.12), xkeyboard-config (2.20),
xorg-x11-proto-devel (7.7).

Security Fix(es) :

  - An integer overflow flaw leading to a heap-based buffer
    overflow was found in libXpm. An attacker could use this
    flaw to crash an application using libXpm via a
    specially crafted XPM file. (CVE-2016-10164)

  - It was discovered that libXdmcp used weak entropy to
    generate session keys. On a multi-user system using
    xdmcp, a local attacker could potentially use
    information available from the process list to brute
    force the key, allowing them to hijack other users'
    sessions. (CVE-2017-2625)

  - It was discovered that libICE used a weak entropy to
    generate keys. A local attacker could potentially use
    this flaw for session hijacking using the information
    available from the process list. (CVE-2017-2626)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=11032
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a41ac0d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:drm-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libICE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libICE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libICE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXdmcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXdmcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXdmcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfont2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdrm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libepoxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libevdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libevdev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libevdev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libevdev-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libfontenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libfontenc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libfontenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvdpau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvdpau-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvdpau-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbcommon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbcommon-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbfile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxkbfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-private-llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-private-llvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-private-llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mesa-vulkan-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vulkan-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"drm-utils-2.4.74-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libICE-1.0.9-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libICE-debuginfo-1.0.9-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libICE-devel-1.0.9-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-1.6.5-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libX11-common-1.6.5-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-debuginfo-1.6.5-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libX11-devel-1.6.5-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXaw-1.0.13-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXaw-debuginfo-1.0.13-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXaw-devel-1.0.13-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-1.1.14-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-debuginfo-1.1.14-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXcursor-devel-1.1.14-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXdmcp-1.1.2-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXdmcp-debuginfo-1.1.2-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXdmcp-devel-1.1.2-6.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfixes-5.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfixes-debuginfo-5.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfixes-devel-5.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-debuginfo-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-devel-1.5.2-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-2.0.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-debuginfo-2.0.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont2-devel-2.0.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXi-1.7.9-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXi-debuginfo-1.7.9-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXi-devel-1.7.9-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXpm-3.5.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXpm-debuginfo-3.5.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXpm-devel-3.5.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrandr-1.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrandr-debuginfo-1.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrandr-devel-1.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrender-0.9.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrender-debuginfo-0.9.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXrender-devel-0.9.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXt-1.1.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXt-debuginfo-1.1.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXt-devel-1.1.5-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXtst-1.2.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXtst-debuginfo-1.2.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXtst-devel-1.2.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXv-1.0.11-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXv-debuginfo-1.0.11-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXv-devel-1.0.11-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXvMC-1.0.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXvMC-debuginfo-1.0.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXvMC-devel-1.0.10-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXxf86vm-1.1.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXxf86vm-debuginfo-1.1.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXxf86vm-devel-1.1.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-2.4.74-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-debuginfo-2.4.74-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libdrm-devel-2.4.74-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-1.3.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-debuginfo-1.3.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libepoxy-devel-1.3.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libevdev-1.5.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libevdev-debuginfo-1.5.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libevdev-devel-1.5.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libevdev-utils-1.5.6-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libfontenc-1.1.3-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libfontenc-debuginfo-1.1.3-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libfontenc-devel-1.1.3-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-1.6.3-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-debuginfo-1.6.3-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libinput-devel-1.6.3-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvdpau-1.1.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvdpau-debuginfo-1.1.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvdpau-devel-1.1.1-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libvdpau-docs-1.1.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-0.24-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libwacom-data-0.24-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-debuginfo-0.24-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwacom-devel-0.24-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-1.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-debuginfo-1.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxcb-devel-1.12-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libxcb-doc-1.12-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbcommon-0.7.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbcommon-debuginfo-0.7.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbcommon-devel-0.7.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbcommon-x11-0.7.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbcommon-x11-devel-0.7.1-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbfile-1.0.9-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbfile-debuginfo-1.0.9-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libxkbfile-devel-1.0.9-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-debuginfo-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-dri-drivers-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-filesystem-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libEGL-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libEGL-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGL-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGL-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGLES-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libGLES-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libOSMesa-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libOSMesa-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libgbm-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libgbm-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libglapi-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libxatracker-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-libxatracker-devel-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-private-llvm-3.9.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-private-llvm-debuginfo-3.9.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-private-llvm-devel-3.9.1-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mesa-vulkan-drivers-17.0.1-6.20170307.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-debuginfo-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"vulkan-devel-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"vulkan-filesystem-1.0.39.1-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xcb-proto-1.12-2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xkeyboard-config-2.20-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xkeyboard-config-devel-2.20-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"xorg-x11-proto-devel-7.7-20.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drm-utils / libICE / libICE-debuginfo / libICE-devel / libX11 / etc");
}
