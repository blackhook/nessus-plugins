#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1217.
#

include("compat.inc");

if (description)
{
  script_id(125600);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/04  9:45:00");

  script_cve_id("CVE-2017-18267", "CVE-2018-10768", "CVE-2018-13988");
  script_xref(name:"ALAS", value:"2019-1217");

  script_name(english:"Amazon Linux 2 : poppler (ALAS-2019-1217)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is a NULL pointer dereference in the AnnotPath::getCoordsLength
function in Annot.h. A crafted input will lead to a remote denial of
service attack. Poppler versions later than 0.41.0 are not
affected.(CVE-2018-10768)

The FoFiType1C::cvtGlyph function in fofi/FoFiType1C.cc in Poppler
allows remote attackers to cause a denial of service (infinite
recursion) via a crafted PDF file, as demonstrated by
pdftops.(CVE-2017-18267)

Poppler contains an out of bounds read vulnerability due to an
incorrect memory access that is not mapped in its memory space, as
demonstrated by pdfunite. This can result in memory corruption and
denial of service. This may be exploitable when a victim opens a
specially crafted PDF file.(CVE-2018-13988)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1217.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update poppler' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"poppler-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-cpp-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-cpp-devel-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-debuginfo-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-demos-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-devel-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-glib-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-glib-devel-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-qt-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-qt-devel-0.26.5-20.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"poppler-utils-0.26.5-20.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-cpp / poppler-cpp-devel / poppler-debuginfo / etc");
}
