#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-290.
#

include("compat.inc");

if (description)
{
  script_id(72746);
  script_version("1.4");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2013-4363");
  script_xref(name:"ALAS", value:"2014-290");

  script_name(english:"Amazon Linux AMI : ruby19 (ALAS-2014-290)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Algorithmic complexity vulnerability in
Gem::Version::ANCHORED_VERSION_PATTERN in lib/rubygems/version.rb in
RubyGems before 1.8.23.2, 1.8.24 through 1.8.26, 2.0.x before 2.0.10,
and 2.1.x before 2.1.5, as used in Ruby 1.9.0 through 2.0.0p247,
allows remote attackers to cause a denial of service (CPU consumption)
via a crafted gem version that triggers a large amount of backtracking
in a regular expression. NOTE: this issue is due to an incomplete fix
for CVE-2013-4287 ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-290.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby19' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ruby19-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-debuginfo-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-devel-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-doc-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-irb-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-libs-1.9.3.545-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-bigdecimal-1.1.0-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-io-console-0.3-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-json-1.5.5-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-minitest-2.5.1-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rake-0.9.2.2-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rdoc-3.9.5-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-1.8.23.2-32.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-devel-1.8.23.2-32.60.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-devel / ruby19-doc / ruby19-irb / etc");
}
