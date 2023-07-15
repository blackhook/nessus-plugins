#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-721.
#

include("compat.inc");

if (description)
{
  script_id(92223);
  script_version("2.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2015-8852");
  script_xref(name:"ALAS", value:"2016-721");

  script_name(english:"Amazon Linux AMI : varnish (ALAS-2016-721)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Varnish 3.x before 3.0.7, when used in certain stacked installations,
allows remote attackers to inject arbitrary HTTP headers and conduct
HTTP response splitting attacks via a header line terminated by a \r
(carriage return) character in conjunction with multiple
Content-Length headers in an HTTP request. (CVE-2015-8852)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-721.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update varnish' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"varnish-3.0.7-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-debuginfo-3.0.7-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-docs-3.0.7-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-libs-3.0.7-1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-libs-devel-3.0.7-1.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "varnish / varnish-debuginfo / varnish-docs / varnish-libs / etc");
}
