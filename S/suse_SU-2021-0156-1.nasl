#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0156-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(145181);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/22");

  script_cve_id("CVE-2020-19667", "CVE-2020-25664", "CVE-2020-25665", "CVE-2020-25666", "CVE-2020-25674", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27750", "CVE-2020-27751", "CVE-2020-27752", "CVE-2020-27753", "CVE-2020-27754", "CVE-2020-27755", "CVE-2020-27756", "CVE-2020-27757", "CVE-2020-27758", "CVE-2020-27759", "CVE-2020-27760", "CVE-2020-27761", "CVE-2020-27762", "CVE-2020-27763", "CVE-2020-27764", "CVE-2020-27765", "CVE-2020-27766", "CVE-2020-27767", "CVE-2020-27768", "CVE-2020-27769", "CVE-2020-27770", "CVE-2020-27771", "CVE-2020-27772", "CVE-2020-27773", "CVE-2020-27774", "CVE-2020-27775", "CVE-2020-27776", "CVE-2020-29599");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ImageMagick (SUSE-SU-2021:0156-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ImageMagick fixes the following issues :

CVE-2020-19667: Fixed a stack-based buffer overflow in XPM coder could
result in a crash (bsc#1179103).

CVE-2020-25664: Fixed a heap-based buffer overflow in PopShortPixel
(bsc#1179202).

CVE-2020-25665: Fixed a heap-based buffer overflow in WritePALMImage
(bsc#1179208).

CVE-2020-25666: Fixed an outside the range of representable values of
type 'int' and signed integer overflow (bsc#1179212).

CVE-2020-25674: Fixed a heap-based buffer overflow in WriteOnePNGImage
(bsc#1179223).

CVE-2020-25675: Fixed an outside the range of representable values of
type 'long' and integer overflow (bsc#1179240).

CVE-2020-25676: Fixed an outside the range of representable values of
type 'long' and integer overflow at MagickCore/pixel.c (bsc#1179244).

CVE-2020-27750: Fixed a division by zero in
MagickCore/colorspace-private.h (bsc#1179260).

CVE-2020-27751: Fixed an integer overflow in
MagickCore/quantum-export.c (bsc#1179269).

CVE-2020-27752: Fixed a heap-based buffer overflow in PopShortPixel in
MagickCore/quantum-private.h (bsc#1179346).

CVE-2020-27753: Fixed memory leaks in AcquireMagickMemory function
(bsc#1179397).

CVE-2020-27754: Fixed an outside the range of representable values of
type 'long' and signed integer overflow at MagickCore/quantize.c
(bsc#1179336).

CVE-2020-27755: Fixed memory leaks in ResizeMagickMemory function in
ImageMagick/MagickCore/memory.c (bsc#1179345).

CVE-2020-27756: Fixed a division by zero at MagickCore/geometry.c
(bsc#1179221).

CVE-2020-27757: Fixed an outside the range of representable values of
type 'unsigned long long' at MagickCore/quantum-private.h
(bsc#1179268).

CVE-2020-27758: Fixed an outside the range of representable values of
type 'unsigned long long' (bsc#1179276).

CVE-2020-27759: Fixed an outside the range of representable values of
type 'int' at MagickCore/quantize.c (bsc#1179313).

CVE-2020-27760: Fixed a division by zero at MagickCore/enhance.c
(bsc#1179281).

CVE-2020-27761: Fixed an outside the range of representable values of
type 'unsigned long' at coders/palm.c (bsc#1179315).

CVE-2020-27762: Fixed an outside the range of representable values of
type 'unsigned char' (bsc#1179278).

CVE-2020-27763: Fixed a division by zero at MagickCore/resize.c
(bsc#1179312).

CVE-2020-27764: Fixed an outside the range of representable values of
type 'unsigned long' at MagickCore/statistic.c (bsc#1179317).

CVE-2020-27765: Fixed a division by zero at MagickCore/segment.c
(bsc#1179311).

CVE-2020-27766: Fixed an outside the range of representable values of
type 'unsigned long' at MagickCore/statistic.c (bsc#1179361).

CVE-2020-27767: Fixed an outside the range of representable values of
type 'float' at MagickCore/quantum.h (bsc#1179322).

CVE-2020-27768: Fixed an outside the range of representable values of
type 'unsigned int' at MagickCore/quantum-private.h (bsc#1179339).

CVE-2020-27769: Fixed an outside the range of representable values of
type 'float' at MagickCore/quantize.c (bsc#1179321).

CVE-2020-27770: Fixed an unsigned offset overflowed at
MagickCore/string.c (bsc#1179343).

CVE-2020-27771: Fixed an outside the range of representable values of
type 'unsigned char' at coders/pdf.c (bsc#1179327).

CVE-2020-27772: Fixed an outside the range of representable values of
type 'unsigned int' at coders/bmp.c (bsc#1179347).

CVE-2020-27773: Fixed a division by zero at MagickCore/gem-private.h
(bsc#1179285).

CVE-2020-27774: Fixed an integer overflow at MagickCore/statistic.c
(bsc#1179333).

CVE-2020-27775: Fixed an outside the range of representable values of
type 'unsigned char' at MagickCore/quantum.h (bsc#1179338).

CVE-2020-27776: Fixed an outside the range of representable values of
type 'unsigned long' at MagickCore/statistic.c (bsc#1179362).

CVE-2020-29599: Fixed a shell command injection in -authenticate
(bsc#1179753).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1179753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-19667/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25664/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25665/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25666/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25674/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25675/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25676/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27750/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27751/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27752/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27754/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27755/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27756/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27758/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27759/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27760/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27761/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27762/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27763/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27764/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27765/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27766/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27768/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27769/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27770/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27771/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27772/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27773/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27774/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27775/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-27776/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-29599/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210156-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3e09703"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-156=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-156=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-156=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-156=1

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-156=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-156=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-156=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-156=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP1-2021-156=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2021-156=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-156=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-156=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-156=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-156=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-156=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-SUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-config-7-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-7_Q16HDRI4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-7_Q16HDRI6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ImageMagick-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"ImageMagick-debugsource-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PerlMagick-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-SUSE-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-config-7-upstream-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-debugsource-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ImageMagick-devel-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagick++-devel-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-7.0.7.34-3.90.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.90.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
