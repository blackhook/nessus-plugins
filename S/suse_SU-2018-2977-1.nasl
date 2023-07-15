#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2977-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120117);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-16323", "CVE-2018-16328", "CVE-2018-16329", "CVE-2018-16413", "CVE-2018-16640", "CVE-2018-16641", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ImageMagick (SUSE-SU-2018:2977-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ImageMagick fixes the following security issues :

CVE-2018-16413: Prevent heap-based buffer over-read in the
PushShortPixel function leading to DoS (bsc#1106989)

CVE-2018-16329: Prevent NULL pointer dereference in the
GetMagickProperty function leading to DoS (bsc#1106858).

CVE-2018-16328: Prevent NULL pointer dereference exists in the
CheckEventLogging function leading to DoS (bsc#1106857).

CVE-2018-16323: ReadXBMImage left data uninitialized when processing
an XBM file that has a negative pixel value. If the affected code was
used as a library loaded into a process that includes sensitive
information, that information sometimes can be leaked via the image
data (bsc#1106855)

CVE-2018-16642: The function InsertRow allowed remote attackers to
cause a denial of service via a crafted image file due to an
out-of-bounds write (bsc#1107616)

CVE-2018-16640: Prevent memory leak in the function ReadOneJNGImage
(bsc#1107619)

CVE-2018-16641: Prevent memory leak in the TIFFWritePhotoshopLayers
function (bsc#1107618).

CVE-2018-16643: The functions ReadDCMImage, ReadPWPImage,
ReadCALSImage, and ReadPICTImage did check the return value of the
fputc function, which allowed remote attackers to cause a denial of
service via a crafted image file (bsc#1107612)

CVE-2018-16644: Added missing check for length in the functions
ReadDCMImage and ReadPICTImage, which allowed remote attackers to
cause a denial of service via a crafted image (bsc#1107609)

CVE-2018-16645: Prevent excessive memory allocation issue in the
functions ReadBMPImage and ReadDIBImage, which allowed remote
attackers to cause a denial of service via a crafted image file
(bsc#1107604)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16323/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16328/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16329/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16413/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16641/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16643/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16645/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182977-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcf99cdf"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2018-2118=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-2118=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-debugsource-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ImageMagick-devel-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-7_Q16HDRI4-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagick++-devel-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickCore-7_Q16HDRI6-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libMagickWand-7_Q16HDRI6-debuginfo-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-7.0.7.34-3.24.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-PerlMagick-debuginfo-7.0.7.34-3.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
