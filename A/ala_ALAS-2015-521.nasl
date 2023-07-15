#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-521.
#

include("compat.inc");

if (description)
{
  script_id(83272);
  script_version("1.2");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2013-2099");
  script_xref(name:"ALAS", value:"2015-521");

  script_name(english:"Amazon Linux AMI : python-tornado (ALAS-2015-521)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way Python's SSL module
implementation performed matching of certain certificate names. A
remote attacker able to obtain a valid certificate that contained
multiple wildcard characters could use this flaw to issue a request to
validate such a certificate, resulting in excessive consumption of
CPU."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-521.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python-tornado' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tornado");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tornado-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tornado");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tornado-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"python26-tornado-2.2.1-7.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tornado-doc-2.2.1-7.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tornado-2.2.1-7.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tornado-doc-2.2.1-7.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26-tornado / python26-tornado-doc / python27-tornado / etc");
}