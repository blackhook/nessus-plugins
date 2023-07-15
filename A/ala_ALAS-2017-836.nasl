#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-836.
#

include("compat.inc");

if (description)
{
  script_id(100637);
  script_version("3.4");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-1024", "CVE-2016-10251", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8654", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-9262", "CVE-2016-9387", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9390", "CVE-2016-9391", "CVE-2016-9392", "CVE-2016-9393", "CVE-2016-9394", "CVE-2016-9560", "CVE-2016-9583", "CVE-2016-9591", "CVE-2016-9600");
  script_xref(name:"ALAS", value:"2017-836");
  script_xref(name:"RHSA", value:"2017:1208");

  script_name(english:"Amazon Linux AMI : jasper (ALAS-2017-836)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A

specially crafted file could cause an application using JasPer to
crash or,

possibly, execute arbitrary code. ( CVE-2016-8654 , CVE-2016-9560 ,
CVE-2016-10249 ,

CVE-2015-5203 , CVE-2015-5221 , CVE-2016-1577 , CVE-2016-8690 ,
CVE-2016-8693 ,

CVE-2016-8884 , CVE-2016-8885 , CVE-2016-9262 , CVE-2016-9591 )

Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A

specially crafted file could cause an application using JasPer to
crash.

(CVE-2016-1867 , CVE-2016-2089 , CVE-2016-2116 , CVE-2016-8691 ,
CVE-2016-8692 ,

CVE-2016-8883 , CVE-2016-9387 , CVE-2016-9388 , CVE-2016-9389 ,
CVE-2016-9390 ,

CVE-2016-9391 , CVE-2016-9392 , CVE-2016-9393 , CVE-2016-9394 ,
CVE-2016-9583 ,

CVE-2016-9600 , CVE-2016-10248 , CVE-2016-10251)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-836.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update jasper' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"jasper-1.900.1-21.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-debuginfo-1.900.1-21.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-devel-1.900.1-21.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-libs-1.900.1-21.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-utils-1.900.1-21.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-devel / jasper-libs / etc");
}
