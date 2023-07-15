#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2481-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(112081);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2017-5852", "CVE-2017-5853", "CVE-2017-5854", "CVE-2017-5855", "CVE-2017-5886", "CVE-2017-6840", "CVE-2017-6844", "CVE-2017-6847", "CVE-2017-7378", "CVE-2017-7379", "CVE-2017-7380", "CVE-2017-7994", "CVE-2017-8054", "CVE-2017-8787", "CVE-2018-5308", "CVE-2018-8001");

  script_name(english:"SUSE SLED12 Security Update : podofo (SUSE-SU-2018:2481-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for podofo fixes the following issues :

  - CVE-2017-5852: The
    PoDoFo::PdfPage::GetInheritedKeyFromObject function
    allowed remote attackers to cause a denial of service
    (infinite loop) via a crafted file (bsc#1023067).

  - CVE-2017-5853: Integer overflow allowed remote attackers
    to have unspecified impact via a crafted file
    (bsc#1023069).

  - CVE-2017-5854: Prevent NULL pointer dereference that
    allowed remote attackers to cause a denial of service
    via a crafted file (bsc#1023070).

  - CVE-2017-5855: The PoDoFo::PdfParser::ReadXRefSubsection
    function allowed remote attackers to cause a denial of
    service (NULL pointer dereference) via a crafted file
    (bsc#1023071).

  - CVE-2017-5886: Prevent heap-based buffer overflow in the
    PoDoFo::PdfTokenizer::GetNextToken function that allowed
    remote attackers to have unspecified impact via a
    crafted file (bsc#1023380).

  - CVE-2017-6847: The PoDoFo::PdfVariant::DelayedLoad
    function allowed remote attackers to cause a denial of
    service (NULL pointer dereference) via a crafted file
    (bsc#1027778).

  - CVE-2017-6844: Buffer overflow in the
    PoDoFo::PdfParser::ReadXRefSubsection function allowed
    remote attackers to have unspecified impact via a
    crafted file (bsc#1027782).

  - CVE-2017-6840: The ColorChanger::GetColorFromStack
    function allowed remote attackers to cause a denial of
    service (invalid read) via a crafted file (bsc#1027787).

  - CVE-2017-7378: The PoDoFo::PdfPainter::ExpandTabs
    function allowed remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted PDF document (bsc#1032017).

  - CVE-2017-7379: The
    PoDoFo::PdfSimpleEncoding::ConvertToEncoding function
    allowed remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted PDF document (bsc#1032018).

  - CVE-2017-7380: Prevent NULL pointer dereference that
    allowed remote attackers to cause a denial of service
    via a crafted PDF document (bsc#1032019).

  - CVE-2017-7994: The function TextExtractor::ExtractText
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted PDF document (bsc#1035534).

  - CVE-2017-8054: The function
    PdfPagesTree::GetPageNodeFromArray allowed remote
    attackers to cause a denial of service (infinite
    recursion and application crash) via a crafted PDF
    document (bsc#1035596).

  - CVE-2017-8787: The
    PoDoFo::PdfXRefStreamParserObject::ReadXRefStreamEntry
    function allowed remote attackers to cause a denial of
    service (heap-based buffer over-read) or possibly have
    unspecified other impact via a crafted PDF file
    (bsc#1037739).

  - CVE-2018-5308: Properly validate memcpy arguments in the
    PdfMemoryOutputStream::Write function to prevent remote
    attackers from causing a denial-of-service or possibly
    have unspecified other impact via a crafted pdf file
    (bsc#1075772).

  - CVE-2018-8001: Prevent heap-based buffer over-read
    vulnerability in UnescapeName() that allowed remote
    attackers to cause a denial-of-service or possibly
    unspecified other impact via a crafted pdf file
    (bsc#1084894).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5852/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5853/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5854/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5855/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5886/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6840/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6844/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6847/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7379/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7380/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7994/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8054/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8787/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5308/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8001/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182481-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d67c0983"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2018-1744=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-1744=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1744=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpodofo0_9_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpodofo0_9_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podofo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podofo-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/23");
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
if (! preg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpodofo0_9_2-0.9.2-3.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpodofo0_9_2-debuginfo-0.9.2-3.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"podofo-debuginfo-0.9.2-3.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"podofo-debugsource-0.9.2-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "podofo");
}
