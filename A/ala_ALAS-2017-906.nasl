#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-906.
#

include("compat.inc");

if (description)
{
  script_id(103603);
  script_version("3.7");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2015-9096", "CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064");
  script_xref(name:"ALAS", value:"2017-906");

  script_name(english:"Amazon Linux AMI : ruby22 / ruby23 (ALAS-2017-906)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SMTP command injection via CRLF sequences in RCPT TO or MAIL FROM
commands in Net::SMTP

A SMTP command injection flaw was found in the way Ruby's Net::SMTP
module handled CRLF sequences in certain SMTP commands. An attacker
could potentially use this flaw to inject SMTP commands in a SMTP
session in order to facilitate phishing attacks or spam campaigns.
(CVE-2015-9096)

Escape sequence injection vulnerability in the Basic authentication of
WEBrick

The Basic authentication code in WEBrick library in Ruby allows remote
attackers to inject terminal emulator escape sequences into its log
and possibly execute arbitrary commands via a crafted user name.
(CVE-2017-10784)

Buffer underrun in OpenSSL ASN1 decode

The decode method in the OpenSSL::ASN1 module in Ruby allows attackers
to cause a denial of service (interpreter crash) via a crafted string.
(CVE-2017-14033)

No size limit in summary length of gem spec

RubyGems is vulnerable to maliciously crafted gem specifications to
cause a denial of service attack against RubyGems clients who have
issued a `query` command. (CVE-2017-0900)

Arbitrary file overwrite due to incorrect validation of specification
name

RubyGems fails to validate specification names, allowing a maliciously
crafted gem to potentially overwrite any file on the filesystem.
(CVE-2017-0901)

DNS hijacking vulnerability

RubyGems is vulnerable to a DNS hijacking vulnerability that allows a
MITM attacker to force the RubyGems client to download and install
gems from a server that the attacker controls. (CVE-2017-0902)

Buffer underrun vulnerability in Kernel.sprintf

Ruby is vulnerable to a malicious format string which contains a
precious specifier (*) with a huge minus value. Such situation can
lead to a buffer overrun, resulting in a heap memory corruption or an
information disclosure from the heap. (CVE-2017-0898)

Escape sequence in the 'summary' field of gemspec

RubyGems is vulnerable to maliciously crafted gem specifications that
include terminal escape characters. Printing the gem specification
would execute terminal escape sequences. (CVE-2017-0899)

Arbitrary heap exposure during a JSON.generate call

Ruby can expose arbitrary memory during a JSON.generate call. The
issues lies in using strdup in ext/json/ext/generator/generator.c,
which will stop after encountering a '\\0' byte, returning a pointer
to a string of length zero, which is not the length stored in
space_len. (CVE-2017-14064)

A vulnerability was found where the rubygems module was vulnerable to
an unsafe YAML deserialization when inspecting a gem. Applications
inspecting gem files without installing them can be tricked to execute
arbitrary code in the context of the ruby interpreter. (CVE-2017-0903)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-906.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update ruby22' to update your system.

Run 'yum update ruby23' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem23-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems23-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");
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
if (rpm_check(release:"ALA", reference:"ruby22-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-debuginfo-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-devel-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-doc-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-irb-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-libs-2.2.8-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-debuginfo-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-devel-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-doc-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-irb-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby23-libs-2.3.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-bigdecimal-1.2.6-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-io-console-0.4.3-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-psych-2.0.8.1-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-bigdecimal-1.2.8-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-did_you_mean-1.0.0-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-io-console-0.4.5-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-json-1.8.3.1-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem23-psych-2.1.0.1-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-2.4.5.2-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-devel-2.4.5.2-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-2.5.2.1-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems23-devel-2.5.2.1-1.17.amzn1")) flag++;

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
