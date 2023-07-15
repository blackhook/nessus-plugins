#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0132-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106186);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-10800", "CVE-2017-11141", "CVE-2017-11449", "CVE-2017-11529", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-11751", "CVE-2017-12430", "CVE-2017-12434", "CVE-2017-12564", "CVE-2017-12642", "CVE-2017-12667", "CVE-2017-12670", "CVE-2017-12672", "CVE-2017-12675", "CVE-2017-13060", "CVE-2017-13146", "CVE-2017-13648", "CVE-2017-13658", "CVE-2017-14249", "CVE-2017-14326", "CVE-2017-14533", "CVE-2017-17680", "CVE-2017-17881", "CVE-2017-17882", "CVE-2017-18022", "CVE-2017-9409", "CVE-2018-5246", "CVE-2018-5247");

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2018:0132-1)");
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

  - CVE-2017-12672: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (bsc#1052720).

  - CVE-2017-13060: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted
    file (bsc#1055065).

  - CVE-2017-11724: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c involving the
    quantum_info and clone_info data structures
    (bsc#1051446).

  - CVE-2017-12670: Added validation in coders/mat.c to
    prevent an assertion failure in the function
    DestroyImage in MagickCore/image.c, which allowed
    attackers to cause a denial of service (bsc#1052731).

  - CVE-2017-12667: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1052732).

  - CVE-2017-13146: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1055323).

  - CVE-2017-10800: Processing MATLAB images in coders/mat.c
    could have lead to a denial of service (OOM) in
    ReadMATImage() if the size specified for a MAT Object
    was larger than the actual amount of data (bsc#1047044)

  - CVE-2017-13648: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1055434).

  - CVE-2017-11141: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders\mat.c that could have
    caused memory exhaustion via a crafted MAT file, related
    to incorrect ordering of a SetImageExtent call
    (bsc#1047898).

  - CVE-2017-11529: The ReadMATImage function in
    coders/mat.c allowed remote attackers to cause a denial
    of service (memory leak) via a crafted file
    (bsc#1050120).

  - CVE-2017-12564: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (bsc#1052468).

  - CVE-2017-12434: Added a missing NULL check in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (assertion
    failure) in DestroyImageInfo in image.c (bsc#1052550).

  - CVE-2017-12675: Added a missing check for
    multidimensional data coders/mat.c, that could have lead
    to a memory leak in the function ReadImage in
    MagickCore/constitute.c, which allowed attackers to
    cause a denial of service (bsc#1052710).

  - CVE-2017-14326: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted
    file (bsc#1058640).

  - CVE-2017-11644: Processesing a crafted file in convert
    could have lead to a memory leak in the ReadMATImage()
    function in coders/mat.c (bsc#1050606).

  - CVE-2017-13658: Added a missing NULL check in the
    ReadMATImage function in coders/mat.c, which could have
    lead to a denial of service (assertion failure and
    application exit) in the DestroyImageInfo function in
    MagickCore/image.c (bsc#1055855).

  - CVE-2017-14533: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1059751).

  - CVE-2017-17881: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted MAT
    image file (bsc#1074123).

  - CVE-2017-1000476: Prevent CPU exhaustion in the function
    ReadDDSInfo in coders/dds.c, which allowed attackers to
    cause a denial of service (bsc#1074610).

  - CVE-2017-9409: Fixed a memory leak vulnerability in the
    function ReadMPCImage in mpc.c, which allowed attackers
    to cause a denial of service via a crafted file
    (bsc#1042948).

  - CVE-2017-11449: coders/mpc did not enable seekable
    streams and thus could not validate blob sizes, which
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via an image received from stdin (bsc#1049373)

  - CVE-2017-12430: A memory exhaustion in the function
    ReadMPCImage in coders/mpc.c allowed attackers to cause
    DoS (bsc#1052252)

  - CVE-2017-12642: Prevent a memory leak vulnerability in
    ReadMPCImage in coders\mpc.c via crafted file allowing
    for DoS (bsc#1052771)

  - CVE-2017-14249: A mishandled EOF check in ReadMPCImage
    in coders/mpc.c that lead to a division by zero in
    GetPixelCacheTileSize in MagickCore/cache.c allowed
    remote attackers to cause a denial of service via a
    crafted file (bsc#1058082)

  - CVE-2017-1000445: Added a NUL pointer check in the
    MagickCore component that might have lead to denial of
    service (bsc#1074425).

  - CVE-2017-11751: Fixed a memory leak vulnerability in the
    function WritePICONImage in coders/xpm.c that allowed
    remote attackers to cause a denial of service via a
    crafted file (bsc#1051412).

  - CVE-2017-17680: Fixed a memory leak vulnerability in the
    function ReadXPMImage in coders/xpm.c, which allowed
    attackers to cause a denial of service via a crafted xpm
    image file (bsc#1072902).

  - CVE-2017-17882: Fixed a memory leak vulnerability in the
    function ReadXPMImage in coders/xpm.c, which allowed
    attackers to cause a denial of service via a crafted XPM
    image file (bsc#1074122).

  - CVE-2018-5246: Fixed memory leak vulnerability in
    ReadPATTERNImage in coders/pattern.c (bsc#1074973).

  - CVE-2017-18022: Fixed memory leak vulnerability in
    MontageImageCommand in MagickWand/montage.c
    (bsc#1074975)

  - CVE-2018-5247: Fixed memory leak vulnerability in
    ReadRLAImage in coders/rla.c (bsc#1074969)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000445/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000476/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10800/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11141/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11449/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11529/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11724/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11751/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12430/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12434/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12564/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12667/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12670/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12675/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13060/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13146/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13648/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14249/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14326/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14533/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17680/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17881/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17882/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18022/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9409/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5246/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5247/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180132-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3cc00d8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-ImageMagick-13422=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-ImageMagick-13422=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-ImageMagick-13422=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.78.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-7.78.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libMagickCore1-6.4.3.6-7.78.22.1")) flag++;


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
