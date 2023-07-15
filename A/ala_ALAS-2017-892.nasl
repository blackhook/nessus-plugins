#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-892.
#

include("compat.inc");

if (description)
{
  script_id(103226);
  script_version("3.6");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7679", "CVE-2017-9788");
  script_xref(name:"ALAS", value:"2017-892");

  script_name(english:"Amazon Linux AMI : httpd (ALAS-2017-892)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in the httpd's mod_ssl
module. A remote attacker could use this flaw to cause an httpd child
process to crash if another module used by httpd called a certain API
function during the processing of an HTTPS request. (CVE-2017-3169)

It was discovered that the use of httpd's ap_get_basic_auth_pw() API
function outside of the authentication phase could lead to
authentication bypass. A remote attacker could possibly use this flaw
to bypass required authentication if the API was used incorrectly by
one of the modules used by httpd. (CVE-2017-3167)

A buffer over-read flaw was found in the httpd's mod_mime module. A
user permitted to modify httpd's MIME configuration could use this
flaw to cause httpd child process to crash. (CVE-2017-7679)

It was discovered that the httpd's mod_auth_digest module did not
properly initialize memory before using it when processing certain
headers related to digest authentication. A remote attacker could
possibly use this flaw to disclose potentially sensitive information
or cause httpd child process to crash by sending specially crafted
requests to a server. (CVE-2017-9788)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-892.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.34-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.34-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.34-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.34-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.34-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.34-1.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
