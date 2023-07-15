#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0349-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106602);
  script_version("3.4");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-10995", "CVE-2017-11505", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11539", "CVE-2017-11639", "CVE-2017-11750", "CVE-2017-12565", "CVE-2017-12640", "CVE-2017-12641", "CVE-2017-12643", "CVE-2017-12671", "CVE-2017-12673", "CVE-2017-12676", "CVE-2017-12935", "CVE-2017-13059", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13147", "CVE-2017-14103", "CVE-2017-14649", "CVE-2017-15218", "CVE-2017-17504", "CVE-2017-17681", "CVE-2017-17879", "CVE-2017-17884", "CVE-2017-17914", "CVE-2017-18008", "CVE-2017-18027", "CVE-2017-18029", "CVE-2017-9261", "CVE-2017-9262", "CVE-2018-5246", "CVE-2018-5685");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ImageMagick (SUSE-SU-2018:0349-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes several issues. These security
issues were fixed :

  - CVE-2017-18027: Prevent memory leak vulnerability in the
    function ReadMATImage which allowed remote attackers to
    cause a denial of service via a crafted file
    (bsc#1076051)

  - CVE-2017-18029: Prevent memory leak in the function
    ReadMATImage which allowed remote attackers to cause a
    denial of service via a crafted file (bsc#1076021)

  - CVE-2017-17681: Prevent infinite loop in the function
    ReadPSDChannelZip in coders/psd.c, which allowed
    attackers to cause a denial of service (CPU exhaustion)
    via a crafted psd image file (bsc#1072901).

  - CVE-2017-18008: Prevent memory Leak in ReadPWPImage
    which allowed attackers to cause a denial of service via
    a PWP file (bsc#1074309).

  - CVE-2018-5685: Prevent infinite loop and application
    hang in the ReadBMPImage function. Remote attackers
    could leverage this vulnerability to cause a denial of
    service via an image file with a crafted bit-field mask
    value (bsc#1075939)

  - CVE-2017-11639: Prevent heap-based buffer over-read in
    the WriteCIPImage() function, related to the
    GetPixelLuma function in MagickCore/pixel-accessor.h
    (bsc#1050635)

  - CVE-2017-11525: Prevent memory consumption in the
    ReadCINImage function that allowed remote attackers to
    cause a denial of service (bsc#1050098)

  - CVE-2017-9262: The ReadJNGImage function in coders/png.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1043353).

  - CVE-2017-9261: The ReadMNGImage function in coders/png.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1043354).

  - CVE-2017-10995: The mng_get_long function in
    coders/png.c allowed remote attackers to cause a denial
    of service (heap-based buffer over-read and application
    crash) via a crafted MNG image (bsc#1047908).

  - CVE-2017-11539: Prevent memory leak in the
    ReadOnePNGImage() function in coders/png.c
    (bsc#1050037).

  - CVE-2017-11505: The ReadOneJNGImage function in
    coders/png.c allowed remote attackers to cause a denial
    of service (large loop and CPU consumption) via a
    crafted file (bsc#1050072).

  - CVE-2017-11526: The ReadOneMNGImage function in
    coders/png.c allowed remote attackers to cause a denial
    of service (large loop and CPU consumption) via a
    crafted file (bsc#1050100).

  - CVE-2017-11750: The ReadOneJNGImage function in
    coders/png.c allowed remote attackers to cause a denial
    of service (NULL pointer dereference) via a crafted file
    (bsc#1051442).

  - CVE-2017-12565: Prevent memory leak in the function
    ReadOneJNGImage in coders/png.c, which allowed attackers
    to cause a denial of service (bsc#1052470).

  - CVE-2017-12676: Prevent memory leak in the function
    ReadOneJNGImage in coders/png.c, which allowed attackers
    to cause a denial of service (bsc#1052708).

  - CVE-2017-12673: Prevent memory leak in the function
    ReadOneMNGImage in coders/png.c, which allowed attackers
    to cause a denial of service (bsc#1052717).

  - CVE-2017-12671: Added NULL assignment in coders/png.c to
    prevent an invalid free in the function
    RelinquishMagickMemory in MagickCore/memory.c, which
    allowed attackers to cause a denial of service
    (bsc#1052721).

  - CVE-2017-12643: Prevent a memory exhaustion
    vulnerability in ReadOneJNGImage in coders\png.c
    (bsc#1052768).

  - CVE-2017-12641: Prevent a memory leak vulnerability in
    ReadOneJNGImage in coders\png.c (bsc#1052777).

  - CVE-2017-12640: Prevent an out-of-bounds read
    vulnerability in ReadOneMNGImage in coders/png.c
    (bsc#1052781).

  - CVE-2017-12935: The ReadMNGImage function in
    coders/png.c mishandled large MNG images, leading to an
    invalid memory read in the SetImageColorCallBack
    function in magick/image.c (bsc#1054600).

  - CVE-2017-13059: Prevent memory leak in the function
    WriteOneJNGImage in coders/png.c, which allowed
    attackers to cause a denial of service (WriteJNGImage
    memory consumption) via a crafted file (bsc#1055068).

  - CVE-2017-13147: Prevent allocation failure in the
    function ReadMNGImage in coders/png.c when a small MNG
    file has a MEND chunk with a large length value
    (bsc#1055374).

  - CVE-2017-13142: Added additional checks for short files
    to prevent a crafted PNG file from triggering a crash
    (bsc#1055455).

  - CVE-2017-13141: Prevent memory leak in ReadOnePNGImage
    in coders/png.c (bsc#1055456).

  - CVE-2017-14103: The ReadJNGImage and ReadOneJNGImage
    functions in coders/png.c did not properly manage image
    pointers after certain error conditions, which allowed
    remote attackers to conduct use-after-free attacks via a
    crafted file, related to a ReadMNGImage out-of-order
    CloseBlob call (bsc#1057000).

  - CVE-2017-14649: ReadOneJNGImage in coders/png.c did not
    properly validate JNG data, leading to a denial of
    service (assertion failure in magick/pixel_cache.c, and
    application crash) (bsc#1060162).

  - CVE-2017-15218: Prevent memory leak in ReadOneJNGImage
    in coders/png.c (bsc#1062752).

  - CVE-2017-17504: Prevent heap-based buffer over-read via
    a crafted file in Magick_png_read_raw_profile, related
    to ReadOneMNGImage (bsc#1072362).

  - CVE-2017-17884: Prevent memory leak in the function
    WriteOnePNGImage in coders/png.c, which allowed
    attackers to cause a denial of service via a crafted PNG
    image file (bsc#1074120).

  - CVE-2017-17879: Prevent heap-based buffer over-read in
    ReadOneMNGImage in coders/png.c, related to length
    calculation and caused by an off-by-one error
    (bsc#1074125).

  - CVE-2017-17914: Prevent crafted files to cause a large
    loop in ReadOneMNGImage (bsc#1074185).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10995/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11505/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11525/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11526/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11750/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12565/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12641/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12643/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12671/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12673/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12676/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12935/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13059/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13141/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13142/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13147/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14103/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15218/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17504/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17681/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17879/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17884/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17914/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18008/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18027/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18029/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9261/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9262/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5246/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5685/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180349-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68e017fd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-244=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2018-244=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-244=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-244=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-244=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-244=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-244=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-244=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-244=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debugsource-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debugsource-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.33.1")) flag++;


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
