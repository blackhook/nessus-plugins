#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2713 and 
# Oracle Linux Security Advisory ELSA-2019-2713 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128846);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2018-18897", "CVE-2018-20481", "CVE-2018-20551", "CVE-2018-20650", "CVE-2018-20662", "CVE-2019-10871", "CVE-2019-12293", "CVE-2019-7310", "CVE-2019-9200", "CVE-2019-9631", "CVE-2019-9903", "CVE-2019-9959");
  script_xref(name:"RHSA", value:"2019:2713");

  script_name(english:"Oracle Linux 8 : poppler (ELSA-2019-2713)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:2713 :

An update for poppler is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Security Fix(es) :

* poppler: heap-based buffer over-read in XRef::getEntry in XRef.cc
(CVE-2019-7310)

* poppler: heap-based buffer overflow in function
ImageStream::getLine() in Stream.cc (CVE-2019-9200)

* poppler: heap-based buffer over-read in function
PSOutputDev::checkPageSlice in PSOutputDev.cc (CVE-2019-10871)

* poppler: heap-based buffer over-read in JPXStream::init in
JPEG2000Stream.cc (CVE-2019-12293)

* poppler: memory leak in GfxColorSpace::setDisplayProfile in
GfxState.cc (CVE-2018-18897)

* poppler: NULL pointer dereference in the XRef::getEntry in XRef.cc
(CVE-2018-20481)

* poppler: reachable Object::getString assertion in AnnotRichMedia
class in Annot.c (CVE-2018-20551)

* poppler: reachable Object::dictLookup assertion in FileSpec class in
FileSpec.cc (CVE-2018-20650)

* poppler: SIGABRT PDFDoc::setup class in PDFDoc.cc (CVE-2018-20662)

* poppler: heap-based buffer over-read in function
downsample_row_box_filter in CairoRescaleBox.cc (CVE-2019-9631)

* poppler: stack consumption in function Dict::find() in Dict.cc
(CVE-2019-9903)

* poppler: integer overflow in JPXStream::init function leading to
memory consumption (CVE-2019-9959)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-September/009153.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-cpp-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-cpp-devel-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-devel-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-glib-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-glib-devel-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-qt5-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-qt5-devel-0.66.0-11.el8_0.12")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"poppler-utils-0.66.0-11.el8_0.12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-devel / etc");
}
