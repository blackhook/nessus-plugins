#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2022 and 
# CentOS Errata and Security Advisory 2019:2022 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128331);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-16646", "CVE-2018-18897", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-19149", "CVE-2018-20481", "CVE-2018-20650", "CVE-2018-20662", "CVE-2019-7310", "CVE-2019-9200", "CVE-2019-9631");
  script_xref(name:"RHSA", value:"2019:2022");

  script_name(english:"CentOS 7 : evince / okular / poppler (CESA-2019:2022)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for poppler, evince, and okular is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince or Okular.

Security Fix(es) :

* poppler: heap-based buffer over-read in XRef::getEntry in XRef.cc
(CVE-2019-7310)

* poppler: heap-based buffer overflow in function
ImageStream::getLine() in Stream.cc (CVE-2019-9200)

* poppler: infinite recursion in Parser::getObj function in Parser.cc
(CVE-2018-16646)

* poppler: memory leak in GfxColorSpace::setDisplayProfile in
GfxState.cc (CVE-2018-18897)

* poppler: reachable abort in Object.h (CVE-2018-19058)

* poppler: out-of-bounds read in EmbFile::save2 in FileSpec.cc
(CVE-2018-19059)

* poppler: pdfdetach utility does not validate save paths
(CVE-2018-19060)

* poppler: NULL pointer dereference in _poppler_attachment_new
(CVE-2018-19149)

* poppler: NULL pointer dereference in the XRef::getEntry in XRef.cc
(CVE-2018-20481)

* poppler: reachable Object::dictLookup assertion in FileSpec class in
FileSpec.cc (CVE-2018-20650)

* poppler: SIGABRT PDFDoc::setup class in PDFDoc.cc (CVE-2018-20662)

* poppler: heap-based buffer over-read in function
downsample_row_box_filter in CairoRescaleBox.cc (CVE-2019-9631)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c974892"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1172af08"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/006052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44002993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince, okular and / or poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:okular-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:okular-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:okular-part");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-browser-plugin-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-devel-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-dvi-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-libs-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"evince-nautilus-3.28.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"okular-4.10.5-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"okular-devel-4.10.5-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"okular-libs-4.10.5-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"okular-part-4.10.5-7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-demos-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"poppler-utils-0.26.5-38.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-devel / evince-dvi / etc");
}
