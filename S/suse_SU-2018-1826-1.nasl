#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1826-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110763);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2016-3632", "CVE-2016-8331", "CVE-2017-11613", "CVE-2017-13726", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-8905");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : tiff (SUSE-SU-2018:1826-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tiff fixes the following issues: These security issues
were fixed :

  - CVE-2017-18013: There was a NULL pointer Dereference in
    the tif_print.c TIFFPrintDirectory function, as
    demonstrated by a tiffinfo crash. (bsc#1074317)

  - CVE-2018-10963: The TIFFWriteDirectorySec() function in
    tif_dirwrite.c allowed remote attackers to cause a
    denial of service (assertion failure and application
    crash) via a crafted file, a different vulnerability
    than CVE-2017-13726. (bsc#1092949)

  - CVE-2018-7456: Prevent a NULL pointer dereference in the
    function TIFFPrintDirectory when using the tiffinfo tool
    to print crafted TIFF information, a different
    vulnerability than CVE-2017-18013 (bsc#1082825)

  - CVE-2017-11613: Prevent denial of service in the
    TIFFOpen function. During the TIFFOpen process,
    td_imagelength is not checked. The value of
    td_imagelength can be directly controlled by an input
    file. In the ChopUpSingleUncompressedStrip function, the
    _TIFFCheckMalloc function is called based on
    td_imagelength. If the value of td_imagelength is set
    close to the amount of system memory, it will hang the
    system or trigger the OOM killer (bsc#1082332)

  - CVE-2018-8905: Prevent heap-based buffer overflow in the
    function LZWDecodeCompat via a crafted TIFF file
    (bsc#1086408)

  - CVE-2016-8331: Prevent remote code execution because of
    incorrect handling of TIFF images. A crafted TIFF
    document could have lead to a type confusion
    vulnerability resulting in remote code execution. This
    vulnerability could have been be triggered via a TIFF
    file delivered to the application using LibTIFF's tag
    extension functionality (bsc#1007276)

  - CVE-2016-3632: The _TIFFVGetField function allowed
    remote attackers to cause a denial of service
    (out-of-bounds write) or execute arbitrary code via a
    crafted TIFF image (bsc#974621)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1007276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=974621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3632/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8331/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11613/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13726/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18013/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10963/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8905/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181826-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d213b90"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1233=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1233=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1233=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtiff5-32bit-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtiff5-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtiff5-debuginfo-32bit-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtiff5-debuginfo-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tiff-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tiff-debuginfo-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tiff-debugsource-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtiff5-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtiff5-debuginfo-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"tiff-debuginfo-4.0.9-44.15.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"tiff-debugsource-4.0.9-44.15.2")) flag++;


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
