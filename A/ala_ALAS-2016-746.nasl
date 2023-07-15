#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-746.
#

include("compat.inc");

if (description)
{
  script_id(93538);
  script_version("2.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-1000212");
  script_xref(name:"ALAS", value:"2016-746");

  script_name(english:"Amazon Linux AMI : lighttpd (ALAS-2016-746)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that lighttpd class did not properly protect against
the HTTP_PROXY variable name clash in a CGI context. A remote attacker
could possibly use this flaw to redirect HTTP requests performed by a
CGI script to an attacker-controlled proxy via a malicious HTTP
request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-746.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update lighttpd' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
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
if (rpm_check(release:"ALA", reference:"lighttpd-1.4.41-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-debuginfo-1.4.41-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-fastcgi-1.4.41-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_geoip-1.4.41-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_mysql_vhost-1.4.41-1.34.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-fastcgi / etc");
}
