#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0486-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106926);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11166", "CVE-2017-11448", "CVE-2017-11450", "CVE-2017-11537", "CVE-2017-11637", "CVE-2017-11638", "CVE-2017-11642", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12429", "CVE-2017-12432", "CVE-2017-12566", "CVE-2017-12654", "CVE-2017-12664", "CVE-2017-12665", "CVE-2017-12668", "CVE-2017-12674", "CVE-2017-13058", "CVE-2017-13131", "CVE-2017-14224", "CVE-2017-17885", "CVE-2017-18028", "CVE-2017-9407", "CVE-2018-6405");

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2018:0486-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2017-9407: In ImageMagick, the ReadPALMImage
    function in palm.c allowed attackers to cause a denial
    of service (memory leak) via a crafted file.
    (bsc#1042824)

  - CVE-2017-11448: The ReadJPEGImage function in
    coders/jpeg.c in ImageMagick allowed remote attackers to
    obtain sensitive information from uninitialized memory
    locations via a crafted file. (bsc#1049375)

  - CVE-2017-11450: A remote denial of service in
    coders/jpeg.c was fixed (bsc#1049374)

  - CVE-2017-11537: When ImageMagick processed a crafted
    file in convert, it can lead to a Floating Point
    Exception (FPE) in the WritePALMImage() function in
    coders/palm.c, related to an incorrect bits-per-pixel
    calculation. (bsc#1050048)

  - CVE-2017-12418: ImageMagick had memory leaks in the
    parse8BIMW and format8BIM functions in coders/meta.c,
    related to the WriteImage function in
    MagickCore/constitute.c. (bsc#1052207)

  - CVE-2017-12432: In ImageMagick, a memory exhaustion
    vulnerability was found in the function ReadPCXImage in
    coders/pcx.c, which allowed attackers to cause a denial
    of service. (bsc#1052254)

  - CVE-2017-12654: The ReadPICTImage function in
    coders/pict.c in ImageMagick allowed attackers to cause
    a denial of service (memory leak) via a crafted file.
    (bsc#1052761)

  - CVE-2017-12664: ImageMagick had a memory leak
    vulnerability in WritePALMImage in coders/palm.c.
    (bsc#1052750)

  - CVE-2017-12665: ImageMagick had a memory leak
    vulnerability in WritePICTImage in coders/pict.c.
    (bsc#1052747)

  - CVE-2017-12668: ImageMagick had a memory leak
    vulnerability in WritePCXImage in coders/pcx.c.
    (bsc#1052688)

  - CVE-2017-13058: In ImageMagick, a memory leak
    vulnerability was found in the function WritePCXImage in
    coders/pcx.c, which allowed attackers to cause a denial
    of service via a crafted file. (bsc#1055069)

  - CVE-2017-14224: A heap-based buffer overflow in
    WritePCXImage in coders/pcx.c could lead to denial of
    service or code execution. (bsc#1058009)

  - CVE-2017-17885: In ImageMagick, a memory leak
    vulnerability was found in the function ReadPICTImage in
    coders/pict.c, which allowed attackers to cause a denial
    of service via a crafted PICT image file. (bsc#1074119)

  - CVE-2017-18028: A memory exhaustion in the function
    ReadTIFFImage in coders/tiff.c was fixed. (bsc#1076182)

  - CVE-2018-6405: In the ReadDCMImage function in
    coders/dcm.c in ImageMagick, each redmap, greenmap, and
    bluemap variable can be overwritten by a new pointer.
    The previous pointer is lost, which leads to a memory
    leak. This allowed remote attackers to cause a denial of
    service. (bsc#1078433)

  - CVE-2017-12427: ProcessMSLScript coders/msl.c allowed
    remote attackers to cause a DoS (bsc#1052248)

  - CVE-2017-12566: A memory leak in ReadMVGImage in
    coders/mvg.c, could have allowed attackers to cause DoS
    (bsc#1052472)

  - CVE-2017-11638, CVE-2017-11642: A NULL pointer
    dereference in theWriteMAPImage() in coders/map.c was
    fixed which could lead to a crash (bsc#1050617)

  - CVE-2017-13131: A memory leak vulnerability was found in
    thefunction ReadMIFFImage in coders/miff.c, which
    allowed attackers tocause a denial of service (memory
    consumption in NewL (bsc#1055229)

  - CVE-2017-11166: In ReadXWDImage in coders\xwd.c a
    memoryleak could have caused memory exhaustion via a
    crafted length (bsc#1048110)

  - CVE-2017-12674: A CPU exhaustion in ReadPDBImage in
    coders/pdb.c was fixed, which allowed attackers to cause
    DoS (bsc#1052711)

  - CVE-2017-12429: A memory exhaustion flaw in
    ReadMIFFImage in coders/miff.c was fixed, which allowed
    attackers to cause DoS (bsc#1052251)

  - CVE-2017-11637: A NULL pointer dereference in
    WritePCLImage() in coders/pcl.c was fixed which could
    lead to a crash (bsc#1050669)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11166/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11537/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11637/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11638/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12418/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12427/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12429/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12432/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12566/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12654/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12664/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12665/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12668/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12674/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13058/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13131/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14224/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17885/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18028/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9407/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6405/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180486-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0a410ee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-ImageMagick-13476=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-ImageMagick-13476=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-ImageMagick-13476=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.78.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-7.78.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libMagickCore1-6.4.3.6-7.78.34.1")) flag++;


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
