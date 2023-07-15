#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-84.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133170);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/24");

  script_cve_id("CVE-2019-5068");

  script_name(english:"openSUSE Security Update : Mesa (openSUSE-2020-84)");
  script_summary(english:"Check for the openSUSE-2020-84 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Mesa fixes the following issues :

Security issue fixed :

  - CVE-2019-5068: Fixed exploitable shared memory
    permissions vulnerability (bsc#1156015).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156015"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Mesa packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-KHR-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-nouveau-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-nouveau-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-dri-nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-drivers-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-gallium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-gallium-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-gallium-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-gallium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libOpenCL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libOpenCL-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libVulkan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libd3d-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libva");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libva-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_radeonsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_radeonsi-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_radeonsi-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_radeonsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_intel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_intel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_radeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_radeon-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_radeon-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvulkan_radeon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"Mesa-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-KHR-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-debugsource-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-dri-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-dri-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-dri-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-dri-nouveau-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-dri-nouveau-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-drivers-debugsource-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-gallium-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-gallium-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libEGL-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libEGL1-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libEGL1-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGL-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGL1-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGL1-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGLESv1_CM-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGLESv1_CM1-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGLESv2-2-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGLESv2-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libGLESv3-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libOpenCL-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libOpenCL-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libVulkan-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libd3d-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libd3d-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libd3d-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libglapi-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libglapi0-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libglapi0-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libva-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"Mesa-libva-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libOSMesa-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libOSMesa8-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libOSMesa8-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libXvMC_nouveau-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libXvMC_nouveau-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libXvMC_r600-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libXvMC_r600-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgbm-devel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgbm1-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgbm1-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_nouveau-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_nouveau-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_r300-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_r300-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_r600-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_r600-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_radeonsi-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvdpau_radeonsi-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvulkan_intel-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvulkan_intel-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvulkan_radeon-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvulkan_radeon-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxatracker-devel-1.0.0-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxatracker2-1.0.0-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxatracker2-debuginfo-1.0.0-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-dri-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-dri-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-dri-nouveau-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-dri-nouveau-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-gallium-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-gallium-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libGL1-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libGL1-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libd3d-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libd3d-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libd3d-devel-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libglapi-devel-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libOSMesa-devel-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libOSMesa8-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libOSMesa8-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libXvMC_nouveau-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libXvMC_nouveau-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libXvMC_r600-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libXvMC_r600-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgbm-devel-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgbm1-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgbm1-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_nouveau-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_nouveau-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_r300-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_r300-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_r600-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_r600-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_radeonsi-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvdpau_radeonsi-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvulkan_intel-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvulkan_intel-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvulkan_radeon-32bit-18.3.2-lp151.23.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libvulkan_radeon-32bit-debuginfo-18.3.2-lp151.23.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mesa-dri / Mesa-dri-debuginfo / Mesa-dri-nouveau / etc");
}
