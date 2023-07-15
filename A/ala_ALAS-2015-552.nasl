#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-552.
#

include("compat.inc");

if (description)
{
  script_id(84369);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/12");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-9365");
  script_xref(name:"ALAS", value:"2015-552");

  script_name(english:"Amazon Linux AMI : python27 (ALAS-2015-552)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict sizes of server responses. A malicious server could cause a
client using one of the affected modules to consume an excessive
amount of memory.(CVE-2013-1752)

It was discovered that the Python xmlrpclib did not restrict the size
of a gzip compressed HTTP responses. A malicious XMLRPC server could
cause an XMLRPC client using xmlrpclib to consume an excessive amount
of memory. (CVE-2013-1753)

The Python standard library HTTP client modules (such as httplib or
urllib) did not perform verification of TLS/SSL certificates when
connecting to HTTPS servers. A man-in-the-middle attacker could use
this flaw to hijack connections and eavesdrop or modify transferred
data.(CVE-2014-9365)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-552.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python27' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"python27-2.7.9-4.114.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-debuginfo-2.7.9-4.114.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-devel-2.7.9-4.114.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libs-2.7.9-4.114.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-test-2.7.9-4.114.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tools-2.7.9-4.114.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / python27-libs / etc");
}
