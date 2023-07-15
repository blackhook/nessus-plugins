#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0055-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(105721);
  script_version("3.5");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-11449", "CVE-2017-11751", "CVE-2017-12430", "CVE-2017-12642", "CVE-2017-14249", "CVE-2017-17680", "CVE-2017-17882", "CVE-2017-9409");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ImageMagick (SUSE-SU-2018:0055-1)");
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

  - CVE-2017-1000476: A CPU exhaustion vulnerability was
    found in the function ReadDDSInfo in coders/dds.c, which
    allowed attackers to cause a denial of service
    (bsc#1074610).

  - CVE-2017-9409: The ReadMPCImage function in mpc.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1042948).

  - CVE-2017-1000445: A NULL pointer dereference in the
    MagickCore component might have lead to denial of
    service (bsc#1074425).

  - CVE-2017-17680: Prevent a memory leak in the function
    ReadXPMImage in coders/xpm.c, which allowed attackers to
    cause a denial of service via a crafted XPM image file
    (a different vulnerability than CVE-2017-17882)
    (bsc#1072902).

  - CVE-2017-17882: Prevent a memory leak in the function
    ReadXPMImage in coders/xpm.c, which allowed attackers to
    cause a denial of service via a crafted XPM image file
    (a different vulnerability than CVE-2017-17680)
    (bsc#1074122).

  - CVE-2017-11449: coders/mpc did not enable seekable
    streams and thus could not validate blob sizes, which
    allowed remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via an image received from stdin (bsc#1049373).

  - CVE-2017-12430: A memory exhaustion in the function
    ReadMPCImage in coders/mpc.c allowed attackers to cause
    DoS (bsc#1052252).

  - CVE-2017-12642: Prevent a memory leak vulnerability in
    ReadMPCImage in coders\mpc.c via crafted file allowing
    for DoS (bsc#1052771).

  - CVE-2017-14249: A mishandled EOF check in ReadMPCImage
    in coders/mpc.c that lead to a division by zero in
    GetPixelCacheTileSize in MagickCore/cache.c allowed
    remote attackers to cause a denial of service via a
    crafted file (bsc#1058082).

  - Prevent memory leak via crafted file in pwp.c allowing
    for DoS (bsc#1051412)

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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058082"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074610"
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
    value:"https://www.suse.com/security/cve/CVE-2017-11449/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-12642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14249/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17680/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17882/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9409/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180055-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10f4c2c2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-41=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2018-41=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-41=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-41=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-41=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-41=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-41=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-41=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-41=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/10");
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
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ImageMagick-debugsource-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ImageMagick-debugsource-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-71.23.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-71.23.1")) flag++;


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
