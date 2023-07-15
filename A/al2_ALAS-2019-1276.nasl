#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1276.
#

include("compat.inc");

if (description)
{
  script_id(128290);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2017-17742", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_xref(name:"ALAS", value:"2019-1276");

  script_name(english:"Amazon Linux 2 : ruby (ALAS-2019-1276)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was found that WEBrick could be forced to use an excessive amount
of memory during the processing of HTTP requests, leading to a Denial
of Service. An attacker could use this flaw to send huge requests to a
WEBrick application, resulting in the server running out of memory.
(CVE-2018-8777)

It was found that the tmpdir and tempfile modules did not sanitize
their file name argument. An attacker with control over the name could
create temporary files and directories outside of the dedicated
directory. (CVE-2018-6914)

It was found that WEBrick did not sanitize headers sent back to
clients, resulting in a response-splitting vulnerability. An attacker,
able to control the server's headers, could force WEBrick into
injecting additional headers to a client. (CVE-2017-17742)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Directory Traversal vulnerability in install_location function of
package.rb that can result in path traversal when writing to a
symlinked basedir outside of the root. This vulnerability appears to
have been fixed in 2.7.6. (CVE-2018-1000073)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Improper Verification of Cryptographic Signature vulnerability in
package.rb that can result in a mis-signed gem could be installed, as
the tarball would contain multiple gem signatures.. This vulnerability
appears to have been fixed in 2.7.6. (CVE-2018-1000076)

It was found that the methods from the Dir class did not properly
handle strings containing the NULL byte. An attacker, able to inject
NULL bytes in a path, could possibly trigger an unspecified behavior
of the ruby script. (CVE-2018-8780)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
infinite loop caused by negative size vulnerability in ruby gem
package tar header that can result in a negative size could cause an
infinite loop.. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000075)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Cross Site Scripting (XSS) vulnerability in gem server display of
homepage attribute that can result in XSS. This attack appear to be
exploitable via the victim must browse to a malicious gem on a
vulnerable gem server. This vulnerability appears to have been fixed
in 2.7.6. (CVE-2018-1000078)

An issue was discovered in Ruby before 2.3.8, 2.4.x before 2.4.5,
2.5.x before 2.5.2, and 2.6.x before 2.6.0-preview3. It does not taint
strings that result from unpacking tainted strings with some formats.
(CVE-2018-16396)

A integer underflow was found in the way String#unpack decodes the
unpacking format. An attacker, able to control the unpack format,
could use this flaw to disclose arbitrary parts of the application's
memory. (CVE-2018-8778)

It was found that the UNIXSocket::open and UNIXServer::open ruby
methods did not handle the NULL byte properly. An attacker, able to
inject NULL bytes in the socket path, could possibly trigger an
unspecified behavior of the ruby script. (CVE-2018-8779)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Deserialization of Untrusted Data vulnerability in owner command that
can result in code execution. This attack appear to be exploitable via
victim must run the `gem owner` command on a gem with a specially
crafted YAML file. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000074)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Improper Input Validation vulnerability in ruby gems specification
homepage attribute that can result in a malicious gem could set an
invalid homepage URL. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000077)

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Directory Traversal vulnerability in gem installation that can result
in the gem could write to arbitrary filesystem locations during
installation. This attack appear to be exploitable via the victim must
install a malicious gem. This vulnerability appears to have been fixed
in 2.7.6. (CVE-2018-1000079)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1276.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8780");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"ruby-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-debuginfo-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-devel-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-doc-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-irb-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-libs-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-tcltk-2.0.0.648-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-bigdecimal-1.2.0-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-io-console-0.4.2-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-json-1.7.7-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-minitest-4.3.2-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-psych-2.0.0-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rake-0.9.6-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rdoc-4.0.0-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-2.0.14.1-36.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-devel-2.0.14.1-36.amzn2.0.1")) flag++;

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
