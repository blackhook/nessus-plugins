#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-987.
#

include("compat.inc");

if (description)
{
  script_id(109369);
  script_version("1.1");
  script_cvs_date("Date: 2018/04/27 12:18:29");

  script_cve_id("CVE-2014-8583");
  script_xref(name:"ALAS", value:"2018-987");

  script_name(english:"Amazon Linux AMI : mod24_wsgi (ALAS-2018-987)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Failure to handle errors when attempting to drop group privileges

mod_wsgi before 4.2.4 for Apache, when creating a daemon process
group, does not properly handle when group privileges cannot be
dropped, which might allow attackers to gain privileges via
unspecified vectors. (CVE-2014-8583)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-987.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mod24_wsgi' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-python35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_wsgi-python36");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"mod24_wsgi-debuginfo-3.5-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_wsgi-python26-3.5-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_wsgi-python27-3.5-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_wsgi-python34-3.5-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_wsgi-python35-3.5-1.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_wsgi-python36-3.5-1.25.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_wsgi-debuginfo / mod24_wsgi-python26 / mod24_wsgi-python27 / etc");
}
