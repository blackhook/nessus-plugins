#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-983.
#

include("compat.inc");

if (description)
{
  script_id(108846);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-17742", "CVE-2017-17790", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_xref(name:"ALAS", value:"2018-983");

  script_name(english:"Amazon Linux AMI : ruby20 / ruby22,ruby23,ruby24 (ALAS-2018-983)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Path traversal when writing to a symlinked basedir outside of the root

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Directory Traversal vulnerability in install_location function of
package.rb that can result in path traversal when writing to a
symlinked basedir outside of the root. This vulnerability appears to
have been fixed in 2.7.6. (CVE-2018-1000073)

Improper verification of signatures in tarball allows to install
mis-signed gem :

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Improper Verification of Cryptographic Signature vulnerability in
package.rb that can result in a mis-signed gem could be installed, as
the tarball would contain multiple gem signatures.. This vulnerability
appears to have been fixed in 2.7.6. (CVE-2018-1000076)

Infinite loop vulnerability due to negative size in tar header causes
Denial of Service

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
infinite loop caused by negative size vulnerability in ruby gem
package tar header that can result in a negative size could cause an
infinite loop.. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000075)

Command injection in lib/resolv.rb:lazy_initialize() allows arbitrary
code execution :

The 'lazy_initialize' function in lib/resolv.rb did not properly
process certain filenames. A remote attacker could possibly exploit
this flaw to inject and execute arbitrary commands. (CVE-2017-17790)

Missing URL validation on spec home attribute allows malicious gem to
set an invalid homepage URL :

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Improper Input Validation vulnerability in ruby gems specification
homepage attribute that can result in a malicious gem could set an
invalid homepage URL. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000077)

XSS vulnerability in homepage attribute when displayed via gem server

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Cross Site Scripting (XSS) vulnerability in gem server display of
homepage attribute that can result in XSS. This attack appear to be
exploitable via the victim must browse to a malicious gem on a
vulnerable gem server. This vulnerability appears to have been fixed
in 2.7.6. (CVE-2018-1000078)

Unsafe Object Deserialization Vulnerability in gem owner allowing
arbitrary code execution on specially crafted YAML

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Deserialization of Untrusted Data vulnerability in owner command that
can result in code execution. This attack appear to be exploitable via
victim must run the `gem owner` command on a gem with a specially
crafted YAML file. This vulnerability appears to have been fixed in
2.7.6. (CVE-2018-1000074)

Path traversal issue during gem installation allows to write to
arbitrary filesystem locations

RubyGems version Ruby 2.2 series: 2.2.9 and earlier, Ruby 2.3 series:
2.3.6 and earlier, Ruby 2.4 series: 2.4.3 and earlier, Ruby 2.5
series: 2.5.0 and earlier, prior to trunk revision 62422 contains a
Directory Traversal vulnerability in gem installation that can result
in the gem could write to arbitrary filesystem locations during
installation. This attack appear to be exploitable via the victim must
install a malicious gem. This vulnerability appears to have been fixed
in 2.7.6. (CVE-2018-1000079)

If a script accepts an external input and outputs it without
modification as a part of HTTP responses, an attacker can use newline
characters to deceive the clients that the HTTP response header is
stopped at there, and can inject fake HTTP responses after the newline
characters to show malicious contents to the clients.(CVE-2017-17742)

The Dir.mktmpdir method introduced by tmpdir library accepts the
prefix and the suffix of the directory which is created as the first
parameter. The prefix can contain relative directory specifiers '../',
so this method can be used to target any directory. So, if a script
accepts an external input as the prefix, and the targeted directory
has inappropriate permissions or the ruby process has inappropriate
privileges, the attacker can create a directory or a file at any
directory.(CVE-2018-6914)

If an attacker sends a large request which contains huge HTTP headers,
WEBrick try to process it on memory, so the request causes the
out-of-memory DoS attack.(CVE-2018-8777)

String#unpack receives format specifiers as its parameter, and can be
specified the position of parsing the data by the specifier @. If a
big number is passed with @, the number is treated as the negative
value, and out-of-buffer read is occurred. So, if a script accepts an
external input as the argument of String#unpack, the attacker can read
data on heaps.(CVE-2018-8778)

UNIXServer.open accepts the path of the socket to be created at the
first parameter. If the path contains NUL (\0) bytes, this method
recognize that the path is completed before the NUL bytes. So, if a
script accepts an external input as the argument of this method, the
attacker can make the socket file in the unintentional path. And,
UNIXSocket.open also accepts the path of the socket to be created at
the first parameter without checking NUL bytes like UNIXServer.open.
So, if a script accepts an external input as the argument of this
method, the attacker can accepts the socket file in the unintentional
path.(CVE-2018-8779)

Dir.open, Dir.new, Dir.entries and Dir.empty? accept the path of the
target directory as their parameter. If the parameter contains NUL
(\0) bytes, these methods recognize that the path is completed before
the NUL bytes. So, if a script accepts an external input as the
argument of these methods, the attacker can make the unintentional
directory traversal.(CVE-2018-8780)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-983.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update ruby20' to update your system.

Run 'yum update ruby22' to update your system.

Run 'yum update ruby23' to update your system.

Run 'yum update ruby24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-libs");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-psych");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"ruby20-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-debuginfo-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-devel-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-doc-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-irb-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-libs-2.0.0.648-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-debuginfo-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-devel-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-doc-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-irb-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-libs-2.2.10-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-debuginfo-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-devel-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-doc-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-irb-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-libs-2.3.7-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-debuginfo-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-devel-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-doc-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-irb-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-libs-2.4.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-bigdecimal-1.2.0-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-io-console-0.4.2-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-psych-2.0.0-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-bigdecimal-1.2.6-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-io-console-0.4.3-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-psych-2.0.8.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-bigdecimal-1.2.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-did_you_mean-1.0.0-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-io-console-0.4.5-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-json-1.8.3.1-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-psych-2.1.0.1-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-bigdecimal-1.3.2-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-did_you_mean-1.1.0-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-io-console-0.4.6-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-json-2.0.4-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-psych-2.2.2-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-xmlrpc-0.2.1-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-2.0.14.1-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-devel-2.0.14.1-1.31.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-2.4.5.2-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-devel-2.4.5.2-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-2.5.2.3-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-devel-2.5.2.3-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-2.6.14.1-1.30.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-devel-2.6.14.1-1.30.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby20 / ruby20-debuginfo / ruby20-devel / ruby20-doc / ruby20-irb / etc");
}
