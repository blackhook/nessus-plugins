#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1416.
#

include('compat.inc');

if (description)
{
  script_id(139550);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2018-16396", "CVE-2020-10663");
  script_xref(name:"ALAS", value:"2020-1416");

  script_name(english:"Amazon Linux AMI : ruby20 (ALAS-2020-1416)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An issue was discovered in Ruby before 2.3.8, 2.4.x before 2.4.5,
2.5.x before 2.5.2, and 2.6.x before 2.6.0-preview3. It does not taint
strings that result from unpacking tainted strings with some formats.
(CVE-2018-16396)

The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through
2.4.9, 2.5 through 2.5.7, and 2.6 through 2.6.5, has an Unsafe Object
Creation Vulnerability. This is quite similar to CVE-2013-0269 , but
does not rely on poor garbage-collection behavior within Ruby.
Specifically, use of JSON parsing methods can lead to creation of a
malicious object within the interpreter, with adverse effects that are
application-dependent. (CVE-2020-10663)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1416.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby20' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"ruby20-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-debuginfo-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-devel-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-doc-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-irb-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-libs-2.0.0.648-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-bigdecimal-1.2.0-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-io-console-0.4.2-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-psych-2.0.0-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-2.0.14.1-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-devel-2.0.14.1-1.33.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby20 / ruby20-debuginfo / ruby20-devel / ruby20-doc / ruby20-irb / etc");
}
