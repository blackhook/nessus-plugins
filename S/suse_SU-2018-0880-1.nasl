#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0880-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108877);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11524", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-13768", "CVE-2017-14314", "CVE-2017-14343", "CVE-2017-14505", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-16352", "CVE-2017-16353", "CVE-2017-18219", "CVE-2017-9500", "CVE-2018-7443", "CVE-2018-8804");

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2018:0880-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes several issues. These security
issues were fixed :

  - CVE-2018-8804: The WriteEPTImage function allowed remote
    attackers to cause a denial of service (double free and
    application crash) or possibly have unspecified other
    impact via a crafted file (bsc#1086011)

  - CVE-2017-11524: The WriteBlob function allowed remote
    attackers to cause a denial of service (assertion
    failure and application exit) via a crafted file
    (bsc#1050087)

  - CVE-2017-18219: Prevent allocation failure in the
    function ReadOnePNGImage, which allowed attackers to
    cause a denial of service via a crafted file that
    triggers an attempt at a large png_pixels array
    allocation (bsc#1084060).

  - CVE-2017-9500: Prevent assertion failure in the function
    ResetImageProfileIterator, which allowed attackers to
    cause a denial of service via a crafted file
    (bsc#1043290)

  - CVE-2017-16353: Prevent memory information disclosure in
    the DescribeImage function caused by a heap-based buffer
    over-read. The portion of the code containing the
    vulnerability is responsible for printing the IPTC
    Profile information contained in the image. This
    vulnerability can be triggered with a specially crafted
    MIFF file. There is an out-of-bounds buffer dereference
    because certain increments were never checked
    (bsc#1066170)

  - CVE-2017-16352: Prevent a heap-based buffer overflow in
    the 'Display visual image directory' feature of the
    DescribeImage() function. One possible way to trigger
    the vulnerability is to run the identify command on a
    specially crafted MIFF format file with the verbose flag
    (bsc#1066168)

  - CVE-2017-14314: Prevent off-by-one error in the
    DrawImage function that allowed remote attackers to
    cause a denial of service (DrawDashPolygon heap-based
    buffer over-read and application crash) via a crafted
    file (bsc#1058630)

  - CVE-2017-13768: Prevent NULL pointer dereference in the
    IdentifyImage function that allowed an attacker to
    perform denial of service by sending a crafted image
    file (bsc#1056434)

  - CVE-2017-14505: Fixed handling of NULL arrays, which
    allowed attackers to perform Denial of Service (NULL
    pointer dereference and application crash in
    AcquireQuantumMemory within MagickCore/memory.c) by
    providing a crafted Image File as input (bsc#1059735)

  - CVE-2018-7443: The ReadTIFFImage function did not
    properly validate the amount of image data in a file,
    which allowed remote attackers to cause a denial of
    service (memory allocation failure in the
    AcquireMagickMemory function in MagickCore/memory.c)
    (bsc#1082792)

  - CVE-2017-15016: Prevent NULL pointer dereference
    vulnerability in ReadEnhMetaFile allowing for denial of
    service (bsc#1082291)

  - CVE-2017-15017: Prevent NULL pointer dereference
    vulnerability in ReadOneMNGImage allowing for denial of
    service (bsc#1082283)

  - CVE-2017-12692: The ReadVIFFImage function allowed
    remote attackers to cause a denial of service (memory
    consumption) via a crafted VIFF file (bsc#1082362)

  - CVE-2017-12693: The ReadBMPImage function allowed remote
    attackers to cause a denial of service (memory
    consumption) via a crafted BMP file (bsc#1082348)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11524/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12691/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12692/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12693/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13768/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14314/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14343/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14505/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15016/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15017/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16352/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16353/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18219/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9500/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7443/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8804/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180880-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b312d73a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-ImageMagick-13549=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-ImageMagick-13549=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-ImageMagick-13549=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-78.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-78.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libMagickCore1-6.4.3.6-78.40.1")) flag++;


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
