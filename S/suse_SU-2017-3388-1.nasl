#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3388-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105409);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-11188", "CVE-2017-11478", "CVE-2017-11523", "CVE-2017-11527", "CVE-2017-11535", "CVE-2017-11640", "CVE-2017-11752", "CVE-2017-12140", "CVE-2017-12435", "CVE-2017-12587", "CVE-2017-12644", "CVE-2017-12662", "CVE-2017-12669", "CVE-2017-12983", "CVE-2017-13134", "CVE-2017-13769", "CVE-2017-14138", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14175", "CVE-2017-14341", "CVE-2017-14342", "CVE-2017-14531", "CVE-2017-14607", "CVE-2017-14682", "CVE-2017-14733", "CVE-2017-14989", "CVE-2017-15217", "CVE-2017-15930", "CVE-2017-16545", "CVE-2017-16546", "CVE-2017-16669");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ImageMagick (SUSE-SU-2017:3388-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2017-14989: use-after-free in RenderFreetype in
    MagickCore/annotate.c could lead to denial of service
    [bsc#1061254]

  - CVE-2017-14682: GetNextToken in MagickCore/token.c heap
    buffer overflow could lead to denial of service
    [bsc#1060176]

  - Memory leak in WriteINLINEImage in coders/inline.c could
    lead to denial of service [bsc#1052744]

  - CVE-2017-14607: out of bounds read flaw related to
    ReadTIFFImagehas could possibly disclose potentially
    sensitive memory [bsc#1059778]

  - CVE-2017-11640: NULL pointer deref in WritePTIFImage()
    in coders/tiff.c [bsc#1050632]

  - CVE-2017-14342: a memory exhaustion vulnerability in
    ReadWPGImage in coders/wpg.c could lead to denial of
    service [bsc#1058485]

  - CVE-2017-14341: Infinite loop in the ReadWPGImage
    function [bsc#1058637]

  - CVE-2017-16546: problem in the function ReadWPGImage in
    coders/wpg.c could lead to denial of service
    [bsc#1067181]

  - CVE-2017-16545: The ReadWPGImage function in
    coders/wpg.c in validation problems could lead to denial
    of service [bsc#1067184]

  - CVE-2017-16669: problem in coders/wpg.c could allow
    remote attackers to cause a denial of service via
    crafted file [bsc#1067409]

  - CVE-2017-14175: Lack of End of File check could lead to
    denial of service [bsc#1057719]

  - CVE-2017-14138: memory leak vulnerability in
    ReadWEBPImage in coders/webp.c could lead to denial of
    service [bsc#1057157]

  - CVE-2017-13769: denial of service issue in function
    WriteTHUMBNAILImage in coders/thumbnail.c [bsc#1056432]

  - CVE-2017-13134: a heap-based buffer over-read was found
    in thefunction SFWScan in coders/sfw.c, which allows
    attackers to cause adenial of service via a crafted
    file. [bsc#1055214]

  - CVE-2017-15217: memory leak in ReadSGIImage in
    coders/sgi.c [bsc#1062750]

  - CVE-2017-11478: ReadOneDJVUImage in coders/djvu.c in
    ImageMagick allows remote attackers to cause a DoS
    [bsc#1049796]

  - CVE-2017-15930: NULL pointer dereference while
    transfering JPEG scanlines could lead to denial of
    service [bsc#1066003]

  - CVE-2017-12983: Heap-based buffer overflow in the
    ReadSFWImage function in coders/sfw.c inImageMagick
    7.0.6-8 allows remote attackers to cause a denial of
    service [bsc#1054757]

  - CVE-2017-14531: memory exhaustion issue in ReadSUNImage
    incoders/sun.c. [bsc#1059666]

  - CVE-2017-12435: Memory exhaustion in ReadSUNImage in
    coders/sun.c, which allows attackers to cause denial of
    service [bsc#1052553]

  - CVE-2017-12587: User controlable large loop in the
    ReadPWPImage in coders\pwp.c could lead to denial of
    service [bsc#1052450]

  - CVE-2017-11523: ReadTXTImage in coders/txt.c allows
    remote attackers to cause a denial of service
    [bsc#1050083]

  - CVE-2017-14173: unction ReadTXTImage is vulnerable to a
    integer overflow that could lead to denial of service
    [bsc#1057729]

  - CVE-2017-11188: ImageMagick: The ReadDPXImage function
    in codersdpx.c in ImageMagick 7.0.6-0 has a largeloop
    vulnerability that can cause CPU exhaustion via a
    crafted DPX file, relatedto lack of an EOF check.
    [bnc#1048457]

  - CVE-2017-11527: ImageMagick: ReadDPXImage in
    coders/dpx.c allows remote attackers to cause DoS
    [bnc#1050116]

  - CVE-2017-11535: GraphicsMagick, ImageMagick: Heap-based
    buffer over-read in WritePSImage() in coders/ps.c
    [bnc#1050139]

  - CVE-2017-11752: ImageMagick: ReadMAGICKImage in
    coders/magick.c allows to cause DoS [bnc#1051441]

  - CVE-2017-12140: ImageMagick: ReadDCMImage in codersdcm.c
    has a ninteger signedness error leading to excessive
    memory consumption [bnc#1051847]

  - CVE-2017-12669: ImageMagick: Memory leak in
    WriteCALSImage in coders/cals.c [bnc#1052689]

  - CVE-2017-12662: GraphicsMagick, ImageMagick: Memory leak
    in WritePDFImage in coders/pdf.c [bnc#1052758]

  - CVE-2017-12644: ImageMagick: Memory leak in ReadDCMImage
    in codersdcm.c [bnc#1052764]

  - CVE-2017-14172: ImageMagick: Lack of end of file check
    in ReadPSImage() could lead to a denial of service
    [bnc#1057730]

  - CVE-2017-14733: GraphicsMagick: Heap overflow on
    ReadRLEImage in coders/rle.c could lead to denial of
    service [bnc#1060577]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11188/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11478/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11523/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11527/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11535/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11752/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12140/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12435/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12587/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12662/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12669/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12983/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13134/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13769/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14138/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14172/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14173/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14175/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14341/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14342/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14531/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14607/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14682/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14733/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14989/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15217/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15930/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16545/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16546/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16669/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173388-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e420b1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-2123=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-2123=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-2123=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-2123=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-2123=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-2123=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-2123=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-2123=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-2123=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-6_Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debugsource-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debugsource-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.17.1")) flag++;


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
