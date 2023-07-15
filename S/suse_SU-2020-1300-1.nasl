#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1300-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(136793);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-9928");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : gstreamer-plugins-base (SUSE-SU-2020:1300-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gstreamer-plugins-base fixes the following issue :

Security issue fixed :

CVE-2019-9928: Fixed a heap-based overflow in the rtsp connection
parser (bsc#1133375).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9928/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201300-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?772bd408"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-1300=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-1300=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP2-2020-1300=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-1300=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-1300=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-1300=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1300=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-1300=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9928");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstAllocators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstApp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstAudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstFft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstPbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstRtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstRtsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstSdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstTag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstVideo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-devel-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gstreamer-plugins-base-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gstreamer-plugins-base-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gstreamer-plugins-base-debugsource-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gstreamer-plugins-base-devel-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gstreamer-plugins-base-doc-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstallocators-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstallocators-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstapp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstapp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstaudio-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstaudio-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstfft-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstfft-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstpbutils-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstpbutils-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstriff-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstriff-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstrtp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstrtp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstrtsp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstrtsp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstsdp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstsdp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgsttag-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgsttag-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstvideo-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libgstvideo-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstAllocators-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstApp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstAudio-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstFft-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstPbutils-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstRtp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstRtsp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstSdp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstTag-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-GstVideo-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gstreamer-plugins-base-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gstreamer-plugins-base-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"gstreamer-plugins-base-debugsource-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstallocators-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstallocators-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstapp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstapp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstaudio-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstaudio-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstfft-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstfft-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstpbutils-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstpbutils-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstriff-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstriff-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstrtp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstrtp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstrtsp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstrtsp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstsdp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstsdp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgsttag-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgsttag-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstvideo-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libgstvideo-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"typelib-1_0-GstFft-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-devel-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gstreamer-plugins-base-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gstreamer-plugins-base-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gstreamer-plugins-base-debugsource-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gstreamer-plugins-base-devel-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gstreamer-plugins-base-doc-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstallocators-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstallocators-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstapp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstapp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstaudio-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstaudio-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstfft-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstfft-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstpbutils-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstpbutils-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstriff-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstriff-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstrtp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstrtp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstrtsp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstrtsp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstsdp-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstsdp-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgsttag-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgsttag-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstvideo-1_0-0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libgstvideo-1_0-0-debuginfo-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstAllocators-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstApp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstAudio-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstFft-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstPbutils-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstRtp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstRtsp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstSdp-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstTag-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-GstVideo-1_0-1.12.5-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"typelib-1_0-GstFft-1_0-1.12.5-3.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-base");
}
