#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0539-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(122608);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id(
    "CVE-2018-0886",
    "CVE-2018-8784",
    "CVE-2018-8785",
    "CVE-2018-8786",
    "CVE-2018-8787",
    "CVE-2018-8788",
    "CVE-2018-8789",
    "CVE-2018-1000852"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : freerdp (SUSE-SU-2019:0539-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for freerdp to version 2.0.0~rc4 fixes the following
issues :

Security issues fixed :

CVE-2018-0886: Fix a remote code execution vulnerability (CredSSP)
(bsc#1085416, bsc#1087240, bsc#1104918)

CVE-2018-8789: Fix several denial of service vulnerabilities in the in
the NTLM Authentication module (bsc#1117965)

CVE-2018-8785: Fix a potential remote code execution vulnerability in
the zgfx_decompress function (bsc#1117967)

CVE-2018-8786: Fix a potential remote code execution vulnerability in
the update_read_bitmap_update function (bsc#1117966)

CVE-2018-8787: Fix a potential remote code execution vulnerability in
the gdi_Bitmap_Decompress function (bsc#1117964)

CVE-2018-8788: Fix a potential remote code execution vulnerability in
the nsc_rle_decode function (bsc#1117963)

CVE-2018-8784: Fix a potential remote code execution vulnerability in
the zgfx_decompress_segment function (bsc#1116708)

CVE-2018-1000852: Fixed a remote memory access in the
drdynvc_process_capability_request function (bsc#1120507)

Other issues: Upgraded to version 2.0.0-rc4 (FATE#326739)

Security and stability improvements, including bsc#1103557 and
bsc#1112028

gateway: multiple fixes and improvements

client/X11: support for rail (remote app) icons was added

The licensing code was re-worked: Per-device licenses are now saved on
the client and used on re-connect: WARNING: this is a change in
FreeRDP behavior regarding licensing. If the old behavior is required,
or no licenses should be saved use the new command line option
+old-license (gh#/FreeRDP/FreeRDP#4979)

Improved order handling - only orders that were enable during
capability exchange are accepted. WARNING and NOTE: some servers do
improperly send orders that weren't negotiated, for such cases the new
command line option /relax-order-checks was added to disable the
strict order checking. If connecting to xrdp the options
/relax-order-checks

*and* +glyph-cache are required. (gh#/FreeRDP/FreeRDP#4926)

Fixed automount issues

Fixed several audio and microphone related issues

Fixed X11 Right-Ctrl ungrab feature

Fixed race condition in rdpsnd channel server.

Disabled SSE2 for ARM and powerpc

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-0886/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000852/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8784/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8785/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8786/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8787/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8788/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8789/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190539-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0290b032");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15:zypper in -t patch
SUSE-SLE-Product-WE-15-2019-539=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-539=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0886");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-wayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuwac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuwac0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uwac0-0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-debugsource-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-server-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-server-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-wayland-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"freerdp-wayland-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuwac0-0-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuwac0-0-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uwac0-0-devel-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-debugsource-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-server-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-server-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-wayland-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"freerdp-wayland-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuwac0-0-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuwac0-0-debuginfo-2.0.0~rc4-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"uwac0-0-devel-2.0.0~rc4-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
