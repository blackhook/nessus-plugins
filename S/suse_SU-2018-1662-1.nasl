#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1662-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110512);
  script_version("1.6");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2017-1000456", "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14520", "CVE-2017-14617", "CVE-2017-14928", "CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9865");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : poppler (SUSE-SU-2018:1662-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for poppler fixes the following issues: These security
issues were fixed :

  - CVE-2017-14517: Prevent NULL pointer dereference in the
    XRef::parseEntry() function via a crafted PDF document
    (bsc#1059066).

  - CVE-2017-9865: Fixed a stack-based buffer overflow
    vulnerability in GfxState.cc that would have allowed
    attackers to facilitate a denial-of-service attack via
    specially crafted PDF documents. (bsc#1045939)

  - CVE-2017-14518: Remedy a floating point exception in
    isImageInterpolationRequired() that could have been
    exploited using a specially crafted PDF document.
    (bsc#1059101)

  - CVE-2017-14520: Remedy a floating point exception in
    Splash::scaleImageYuXd() that could have been exploited
    using a specially crafted PDF document. (bsc#1059155)

  - CVE-2017-14617: Fixed a floating point exception in
    Stream.cc, which may lead to a potential attack when
    handling malicious PDF files. (bsc#1060220)

  - CVE-2017-14928: Fixed a NULL pointer dereference in
    AnnotRichMedia::Configuration::Configuration() in
    Annot.cc, which may lead to a potential attack when
    handling malicious PDF files. (bsc#1061092)

  - CVE-2017-14975: Fixed a NULL pointer dereference
    vulnerability, that existed because a data structure in
    FoFiType1C.cc was not initialized, which allowed an
    attacker to launch a denial of service attack.
    (bsc#1061263)

  - CVE-2017-14976: Fixed a heap-based buffer over-read
    vulnerability in FoFiType1C.cc that occurred when an
    out-of-bounds font dictionary index was encountered,
    which allowed an attacker to launch a denial of service
    attack. (bsc#1061264)

  - CVE-2017-14977: Fixed a NULL pointer dereference
    vulnerability in the FoFiTrueType::getCFFBlock()
    function in FoFiTrueType.cc that occurred due to lack of
    validation of a table pointer, which allows an attacker
    to launch a denial of service attack. (bsc#1061265)

  - CVE-2017-15565: Prevent NULL pointer dereference in the
    GfxImageColorMap::getGrayLine() function via a crafted
    PDF document (bsc#1064593).

  - CVE-2017-1000456: Validate boundaries in
    TextPool::addWord to prevent overflows in subsequent
    calculations (bsc#1074453).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000456/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14517/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14518/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14520/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14617/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14928/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14975/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14976/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14977/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15565/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9865/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181662-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1324bc45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1125=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1125=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1125=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-glib8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-qt4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler60-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:poppler-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:poppler-qt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:poppler-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/13");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler-glib8-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler-glib8-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler-qt4-4-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler-qt4-4-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler60-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpoppler60-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"poppler-debugsource-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"poppler-qt-debugsource-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"poppler-tools-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"poppler-tools-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler-glib8-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler-glib8-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler-qt4-4-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler-qt4-4-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler60-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpoppler60-debuginfo-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"poppler-debugsource-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"poppler-qt-debugsource-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"poppler-tools-0.43.0-16.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"poppler-tools-debuginfo-0.43.0-16.15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
