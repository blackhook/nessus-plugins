#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1179-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109674);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-7554", "CVE-2016-10095", "CVE-2016-10268", "CVE-2016-3945", "CVE-2016-5318", "CVE-2016-5652", "CVE-2016-9453", "CVE-2016-9536", "CVE-2017-11335", "CVE-2017-17973", "CVE-2017-9935");

  script_name(english:"SUSE SLES11 Security Update : tiff (SUSE-SU-2018:1179-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

  - CVE-2016-9453: The t2p_readwrite_pdf_image_tile function
    allowed remote attackers to cause a denial of service
    (out-of-bounds write and crash) or possibly execute
    arbitrary code via a JPEG file with a TIFFTAG_JPEGTABLES
    of length one (bsc#1011107).

  - CVE-2016-5652: An exploitable heap-based buffer overflow
    existed in the handling of TIFF images in the TIFF2PDF
    tool. A crafted TIFF document can lead to a heap-based
    buffer overflow resulting in remote code execution.
    Vulnerability can be triggered via a saved TIFF file
    delivered by other means (bsc#1007280).

  - CVE-2017-11335: There is a heap-based buffer overflow in
    tools/tiff2pdf.c via a PlanarConfig=Contig image, which
    caused a more than one hundred bytes out-of-bounds write
    (related to the ZIPDecode function in tif_zip.c). A
    crafted input may lead to a remote denial of service
    attack or an arbitrary code execution attack
    (bsc#1048937).

  - CVE-2016-9536: tools/tiff2pdf.c had an out-of-bounds
    write vulnerabilities in heap allocated buffers in
    t2p_process_jpeg_strip(). Reported as MSVR 35098, aka
    't2p_process_jpeg_strip heap-buffer-overflow.'
    (bsc#1011845)

  - CVE-2017-9935: In LibTIFF, there was a heap-based buffer
    overflow in the t2p_write_pdf function in
    tools/tiff2pdf.c. This heap overflow could lead to
    different damages. For example, a crafted TIFF document
    can lead to an out-of-bounds read in TIFFCleanup, an
    invalid free in TIFFClose or t2p_free, memory corruption
    in t2p_readwrite_pdf_image, or a double free in
    t2p_free. Given these possibilities, it probably could
    cause arbitrary code execution (bsc#1046077).

  - CVE-2017-17973: There is a heap-based use-after-free in
    the t2p_writeproc function in tiff2pdf.c. (bsc#1074318)

  - CVE-2015-7554: The _TIFFVGetField function in tif_dir.c
    allowed attackers to cause a denial of service (invalid
    memory write and crash) or possibly have unspecified
    other impact via crafted field data in an extension tag
    in a TIFF image (bsc#960341).

  - CVE-2016-5318: Stack-based buffer overflow in the
    _TIFFVGetField function allowed remote attackers to
    crash the application via a crafted tiff (bsc#983436).

  - CVE-2016-10095: Stack-based buffer overflow in the
    _TIFFVGetField function in tif_dir.c allowed remote
    attackers to cause a denial of service (crash) via a
    crafted TIFF file (bsc#1017690,).

  - CVE-2016-10268: tools/tiffcp.c allowed remote attackers
    to cause a denial of service (integer underflow and
    heap-based buffer under-read) or possibly have
    unspecified other impact via a crafted TIFF image,
    related to 'READ of size 78490' and
    libtiff/tif_unix.c:115:23 (bsc#1031255)

  - An overlapping of memcpy parameters was fixed which
    could lead to content corruption (bsc#1017691).

  - Fixed an invalid memory read which could lead to a crash
    (bsc#1017692).

  - Fixed a NULL pointer dereference in TIFFReadRawData
    (tiffinfo.c) that could crash the decoder (bsc#1017688).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=983436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7554/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10095/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10268/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3945/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5318/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5652/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9453/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9536/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11335/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17973/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9935/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181179-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e4baba2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-tiff-13594=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-tiff-13594=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-tiff-13594=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/10");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.169.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtiff3-32bit-3.8.2-141.169.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtiff3-3.8.2-141.169.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"tiff-3.8.2-141.169.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
