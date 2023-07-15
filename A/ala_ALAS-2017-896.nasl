#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-896.
#

include("compat.inc");

if (description)
{
  script_id(103309);
  script_version("3.7");
  script_cvs_date("Date: 2019/04/10 16:10:16");

  script_cve_id("CVE-2017-9798");
  script_xref(name:"ALAS", value:"2017-896");

  script_name(english:"Amazon Linux AMI : httpd24 / httpd (ALAS-2017-896) (Optionsbleed)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache httpd allows remote attackers to read secret data from process
memory if the Limit directive can be set in a user's .htaccess file,
or if httpd.conf has certain misconfigurations, aka Optionsbleed. The
attacker sends an unauthenticated OPTIONS HTTP request when attempting
to read secret data. This is a use-after-free issue and thus secret
data is not always sent, and the specific data depends on many factors
including configuration.(CVE-2017-9798)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-896.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update httpd24' to update your system.

Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.34-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.34-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.34-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.34-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.34-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.27-3.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.34-1.15.amzn1")) flag++;

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
