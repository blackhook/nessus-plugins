#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-800.
#

include("compat.inc");

if (description)
{
  script_id(97329);
  script_version("3.4");
  script_cvs_date("Date: 2019/06/04  9:45:00");

  script_cve_id("CVE-2016-5616", "CVE-2016-6662", "CVE-2016-6663");
  script_xref(name:"ALAS", value:"2017-800");

  script_name(english:"Amazon Linux AMI : mysql51 (ALAS-2017-800)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the MySQL logging functionality allowed writing
to MySQL configuration files. An administrative database user, or a
database user with FILE privileges, could possibly use this flaw to
run arbitrary commands with root privileges on the system running the
database server. (CVE-2016-6662)

A race condition was found in the way MySQL performed MyISAM engine
table repair. A database user with shell access to the server running
mysqld could use this flaw to change permissions of arbitrary files
writable by the mysql system user. (CVE-2016-5616 , CVE-2016-6663)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-800.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql51' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (rpm_check(release:"ALA", reference:"mysql51-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-bench-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-common-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-debuginfo-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-devel-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-devel-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-libs-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-server-5.1.73-8.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-test-5.1.73-8.72.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql51 / mysql51-bench / mysql51-common / mysql51-debuginfo / etc");
}
