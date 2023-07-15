#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2147-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(139406);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-15652", "CVE-2020-15653", "CVE-2020-15654", "CVE-2020-15655", "CVE-2020-15656", "CVE-2020-15657", "CVE-2020-15658", "CVE-2020-15659", "CVE-2020-6463", "CVE-2020-6514");
  script_xref(name:"IAVA", value:"2020-A-0344-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2020:2147-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

This update for MozillaFirefox and pipewire fixes the following 
issues :

MozillaFirefox Extended Support Release 78.1.0 ESR

Fixed: Various stability, functionality, and security fixes
(bsc#1174538)

CVE-2020-15652: Potential leak of redirect targets when loading
scripts in a worker

CVE-2020-6514: WebRTC data channel leaks internal address to peer

CVE-2020-15655: Extension APIs could be used to bypass Same-Origin
Policy

CVE-2020-15653: Bypassing iframe sandbox when allowing popups

CVE-2020-6463: Use-after-free in ANGLE
gl::Texture::onUnbindAsSamplerTexture

CVE-2020-15656: Type confusion for special arguments in IonMonkey

CVE-2020-15658: Overriding file type when saving to disk

CVE-2020-15657: DLL hijacking due to incorrect loading path

CVE-2020-15654: Custom cursor can overlay user interface

CVE-2020-15659: Memory safety bugs fixed in Firefox 79 and Firefox ESR
78.1

pipewire was updated to version 0.3.6 (bsc#1171433, jsc#ECO-2308) :

Extensive memory leak fixing and stress testing was done. A big leak
in screen sharing with DMA-BUF was fixed.

Compile fixes

Stability improvements in jack and pulseaudio layers.

Added the old portal module to make the Camera portal work again. This
will be moved to the session manager in future versions.

Improvements to the GStreamer source and sink shutdown.

Fix compatibility with v2 clients again when negotiating buffers.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15652/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15653/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15654/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15655/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15656/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15657/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15659/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-6463/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-6514/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202147-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2265ffe8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2020-2147=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15659");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpipewire-0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpipewire-0_3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-spa-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-spa-plugins-0_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-spa-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-spa-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pipewire-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-devel-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-branding-SLE-78-9.2.4")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-debuginfo-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-debugsource-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-translations-common-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"MozillaFirefox-translations-other-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libpipewire-0_3-0-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libpipewire-0_3-0-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-debugsource-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-modules-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-modules-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-spa-plugins-0_2-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-spa-plugins-0_2-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-spa-tools-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-spa-tools-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-tools-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"pipewire-tools-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-devel-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-branding-SLE-78-9.2.4")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-debuginfo-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-debugsource-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-translations-common-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"MozillaFirefox-translations-other-78.1.0-8.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libpipewire-0_3-0-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libpipewire-0_3-0-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-debugsource-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-modules-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-modules-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-spa-plugins-0_2-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-spa-plugins-0_2-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-spa-tools-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-spa-tools-debuginfo-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-tools-0.3.6-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"pipewire-tools-debuginfo-0.3.6-3.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
