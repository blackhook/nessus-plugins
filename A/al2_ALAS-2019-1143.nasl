#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1143.
#

include("compat.inc");

if (description)
{
  script_id(121052);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/26");

  script_cve_id("CVE-2018-16395");
  script_xref(name:"ALAS", value:"2019-1143");

  script_name(english:"Amazon Linux 2 : ruby (ALAS-2019-1143)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in the OpenSSL library in Ruby. When two
OpenSSL::X509::Name objects are compared using ==, depending on the
ordering, non-equal objects may return true. When the first argument
is one character longer than the second, or the second argument
contains a character that is one less than a character in the same
position of the first argument, the result of == will be true. This
could be leveraged to create an illegitimate certificate that may be
accepted as legitimate and then used in signing or encryption
operations.(CVE-2018-16395)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1143.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"ruby-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-debuginfo-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-devel-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-doc-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-irb-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-libs-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-tcltk-2.0.0.648-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-bigdecimal-1.2.0-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-io-console-0.4.2-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-json-1.7.7-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-minitest-4.3.2-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-psych-2.0.0-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rake-0.9.6-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rdoc-4.0.0-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-2.0.14.1-34.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-devel-2.0.14.1-34.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
}
