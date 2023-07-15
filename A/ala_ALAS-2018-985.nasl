#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-985.
#

include("compat.inc");

if (description)
{
  script_id(108848);
  script_version("1.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-6893", "CVE-2018-5950");
  script_xref(name:"ALAS", value:"2018-985");

  script_name(english:"Amazon Linux AMI : mailman (ALAS-2018-985)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Cross-site scripting (XSS) vulnerability in web UI

A cross-site scripting (XSS) flaw was found in mailman. An attacker,
able to trick the user into visiting a specific URL, can execute
arbitrary web scripts on the user's side and force the victim to
perform unintended actions. (CVE-2018-5950)

CSRF protection missing in the user options page

Cross-site request forgery (CSRF) vulnerability in the user options
page in GNU Mailman 2.1.x before 2.1.23 allows remote attackers to
hijack the authentication of arbitrary users for requests that modify
an option, as demonstrated by gaining access to the credentials of a
victim's account. (CVE-2016-6893)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-985.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mailman' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"mailman-2.1.15-26.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mailman-debuginfo-2.1.15-26.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo");
}
