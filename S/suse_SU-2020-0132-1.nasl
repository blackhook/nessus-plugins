#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0132-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133138);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-5068");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : Mesa (SUSE-SU-2020:0132-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for Mesa fixes the following issues :

Security issue fixed :

CVE-2019-5068: Fixed exploitable shared memory permissions
vulnerability (bsc#1156015).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-5068/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200132-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbf94a0f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15 :

zypper in -t patch SUSE-SLE-Product-WE-15-2020-132=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-132=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-OBS-15-2020-132=1

SUSE Linux Enterprise Module for Basesystem 15 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-2020-132=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-dri-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-dri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-dri-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-drivers-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-gallium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-gallium-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-gallium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv1_CM-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv1_CM1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libOpenCL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libOpenCL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libVulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libd3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libd3d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libd3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libva");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libva-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libOSMesa8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libOSMesa8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_r300");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_r300-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_r600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_r600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_radeonsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvdpau_radeonsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvulkan_intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvulkan_intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvulkan_radeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvulkan_radeon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwayland-egl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwayland-egl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwayland-egl1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxatracker2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxatracker2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libwayland-egl-devel-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"Mesa-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwayland-egl-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-dri-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-dri-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-gallium-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-gallium-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libGL1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libGL1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libVulkan-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libva-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"Mesa-libva-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgbm1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgbm1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_r300-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_r300-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_r600-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_r600-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_radeonsi-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvdpau_radeonsi-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvulkan_intel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvulkan_intel-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvulkan_radeon-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libvulkan_radeon-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libxatracker-devel-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libxatracker2-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libxatracker2-debuginfo-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-dri-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-dri-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-dri-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-drivers-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-gallium-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-gallium-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libEGL-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libEGL1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libEGL1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGL-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGL1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGL1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGLESv1_CM-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGLESv1_CM1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGLESv2-2-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGLESv2-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libGLESv3-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libOpenCL-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libOpenCL-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libglapi-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libglapi0-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"Mesa-libglapi0-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libOSMesa-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libOSMesa8-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libOSMesa8-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgbm-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgbm1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgbm1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwayland-egl-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwayland-egl1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwayland-egl1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libwayland-egl-devel-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"Mesa-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwayland-egl-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-dri-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-dri-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-gallium-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-gallium-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libGL1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libGL1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libVulkan-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libd3d-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libva-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"Mesa-libva-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgbm1-32bit-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgbm1-32bit-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_r300-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_r300-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_r600-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_r600-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_radeonsi-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvdpau_radeonsi-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvulkan_intel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvulkan_intel-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvulkan_radeon-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libvulkan_radeon-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libxatracker-devel-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libxatracker2-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libxatracker2-debuginfo-1.0.0-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-dri-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-dri-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-dri-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-drivers-debugsource-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-gallium-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-gallium-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libEGL-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libEGL1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libEGL1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGL-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGL1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGL1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGLESv1_CM-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGLESv1_CM1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGLESv2-2-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGLESv2-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libGLESv3-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libOpenCL-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libOpenCL-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libglapi-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libglapi0-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"Mesa-libglapi0-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libOSMesa-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libOSMesa8-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libOSMesa8-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgbm-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgbm1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgbm1-debuginfo-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwayland-egl-devel-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwayland-egl1-18.0.2-27.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwayland-egl1-debuginfo-18.0.2-27.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mesa");
}
