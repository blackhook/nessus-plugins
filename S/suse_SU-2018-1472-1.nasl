#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1472-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110258);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10267", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-5314", "CVE-2016-5315", "CVE-2017-18013", "CVE-2017-7593", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602");

  script_name(english:"SUSE SLES11 Security Update : tiff (SUSE-SU-2018:1472-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues: Security issues 
fixed :

  - CVE-2016-5315: The setByteArray function in tif_dir.c
    allowed remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted tiff image.
    (bsc#984809)

  - CVE-2016-10267: LibTIFF allowed remote attackers to
    cause a denial of service (divide-by-zero error and
    application crash) via a crafted TIFF image, related to
    libtiff/tif_ojpeg.c:816:8. (bsc#1017694)

  - CVE-2016-10269: LibTIFF allowed remote attackers to
    cause a denial of service (heap-based buffer over-read)
    or possibly have unspecified other impact via a crafted
    TIFF image, related to 'READ of size 512' and
    libtiff/tif_unix.c:340:2. (bsc#1031254)

  - CVE-2016-10270: LibTIFF allowed remote attackers to
    cause a denial of service (heap-based buffer over-read)
    or possibly have unspecified other impact via a crafted
    TIFF image, related to 'READ of size 8' and
    libtiff/tif_read.c:523:22. (bsc#1031250)

  - CVE-2017-18013: In LibTIFF, there was a NULL pointer
    Dereference in the tif_print.c TIFFPrintDirectory
    function, as demonstrated by a tiffinfo crash.
    (bsc#1074317)

  - CVE-2017-7593: tif_read.c did not ensure that
    tif_rawdata is properly initialized, which might have
    allowed remote attackers to obtain sensitive information
    from process memory via a crafted image. (bsc#1033129)

  - CVE-2017-7595: The JPEGSetupEncode function in
    tiff_jpeg.c allowed remote attackers to cause a denial
    of service (divide-by-zero error and application crash)
    via a crafted image. (bsc#1033127)

  - CVE-2017-7596: LibTIFF had an 'outside the range of
    representable values of type float' undefined behavior
    issue, which might have allowed remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image. (bsc#1033126)

  - CVE-2017-7597: tif_dirread.c had an 'outside the range
    of representable values of type float' undefined
    behavior issue, which might have allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image. (bsc#1033120)

  - CVE-2017-7599: LibTIFF had an 'outside the range of
    representable values of type short' undefined behavior
    issue, which might have allowed remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image. (bsc#1033113)

  - CVE-2017-7600: LibTIFF had an 'outside the range of
    representable values of type unsigned char' undefined
    behavior issue, which might have allowed remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted image. (bsc#1033112)

  - CVE-2017-7601: LibTIFF had a 'shift exponent too large
    for 64-bit type long' undefined behavior issue, which
    might have allowed remote attackers to cause a denial of
    service (application crash) or possibly have unspecified
    other impact via a crafted image. (bsc#1033111)

  - CVE-2017-7602: LibTIFF had a signed integer overflow,
    which might have allowed remote attackers to cause a
    denial of service (application crash) or possibly have
    unspecified other impact via a crafted image.
    (bsc#1033109)

  - Multiple divide by zero issues

  - CVE-2016-5314: Buffer overflow in the PixarLogDecode
    function in tif_pixarlog.c allowed remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    TIFF image, as demonstrated by overwriting the
    vgetparent function pointer with rgb2ycbcr. (bsc#987351
    bsc#984808 bsc#984831)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1033129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=984831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=987351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10267/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10269/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10270/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5314/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5315/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18013/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7593/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7595/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7596/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7597/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7599/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7600/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7601/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7602/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181472-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f76228cb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-tiff-13631=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-tiff-13631=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-tiff-13631=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.169.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtiff3-32bit-3.8.2-141.169.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtiff3-3.8.2-141.169.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"tiff-3.8.2-141.169.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
