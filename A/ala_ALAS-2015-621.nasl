#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-621.
#

include("compat.inc");

if (description)
{
  script_id(87347);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/27");

  script_cve_id("CVE-2013-1752", "CVE-2014-4650", "CVE-2014-7185");
  script_xref(name:"ALAS", value:"2015-621");

  script_name(english:"Amazon Linux AMI : python26 (ALAS-2015-621)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in the way the buffer() function
handled its offset and size arguments. An attacker able to control
those arguments could use this flaw to disclose portions of the
application memory or cause it to crash.

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict sizes of server responses. A malicious server could cause a
client using one of the affected modules to consume an excessive
amount of memory.

It was discovered that the CGIHTTPServer module incorrectly handled
URL encoded paths. A remote attacker could use this flaw to execute
scripts outside of the cgi-bin directory, or disclose source of
scripts in the cgi-bin directory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-621.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python26' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
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
if (rpm_check(release:"ALA", reference:"python26-2.6.9-2.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-debuginfo-2.6.9-2.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-devel-2.6.9-2.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-libs-2.6.9-2.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-test-2.6.9-2.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tools-2.6.9-2.83.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26 / python26-debuginfo / python26-devel / python26-libs / etc");
}
