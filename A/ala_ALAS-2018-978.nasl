#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-978.
#

include("compat.inc");

if (description)
{
  script_id(108603);
  script_version("1.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-0903");
  script_xref(name:"ALAS", value:"2018-978");

  script_name(english:"Amazon Linux AMI : ruby24 / ruby22,ruby23 (ALAS-2018-978)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Unsafe object deserialization through YAML formatted gem
specifications :

A vulnerability was found where the rubygems module was vulnerable to
an unsafe YAML deserialization when inspecting a gem. Applications
inspecting gem files without installing them can be tricked to execute
arbitrary code in the context of the ruby interpreter. (CVE-2017-0903)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-978.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update ruby24' to update your system.

Run 'yum update ruby22' to update your system.

Run 'yum update ruby23' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby23-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
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
if (rpm_check(release:"ALA", reference:"ruby22-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-debuginfo-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-devel-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-doc-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-irb-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-libs-2.2.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-debuginfo-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-devel-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-doc-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-irb-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-libs-2.3.6-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-debuginfo-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-devel-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-doc-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-irb-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-libs-2.4.3-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-bigdecimal-1.2.6-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-io-console-0.4.3-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-psych-2.0.8.1-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-bigdecimal-1.2.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-did_you_mean-1.0.0-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-io-console-0.4.5-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-json-1.8.3.1-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-psych-2.1.0.1-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-bigdecimal-1.3.0-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-did_you_mean-1.1.0-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-io-console-0.4.6-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-json-2.0.4-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-psych-2.2.2-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-xmlrpc-0.2.1-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-2.4.5.2-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-devel-2.4.5.2-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-2.5.2.2-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-devel-2.5.2.2-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-2.6.14-1.30.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-devel-2.6.14-1.30.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby22 / ruby22-debuginfo / ruby22-devel / ruby22-doc / ruby22-irb / etc");
}
