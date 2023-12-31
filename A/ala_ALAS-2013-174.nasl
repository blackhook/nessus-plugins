#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-174.
#

include("compat.inc");

if (description)
{
  script_id(69733);
  script_version("1.7");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558");
  script_xref(name:"ALAS", value:"2013-174");

  script_name(english:"Amazon Linux AMI : httpd (ALAS-2013-174)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple cross-site scripting (XSS) vulnerabilities in the
balancer_handler function in the manager interface in
mod_proxy_balancer.c in the mod_proxy_balancer module in the Apache
HTTP Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow
remote attackers to inject arbitrary web script or HTML via a crafted
string.

Multiple cross-site scripting (XSS) vulnerabilities in the Apache HTTP
Server 2.2.x before 2.2.24-dev and 2.4.x before 2.4.4 allow remote
attackers to inject arbitrary web script or HTML via vectors involving
hostnames and URIs in the (1) mod_imagemap, (2) mod_info, (3)
mod_ldap, (4) mod_proxy_ftp, and (5) mod_status modules."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-174.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.24-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.24-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.24-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.24-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.24-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.24-1.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
