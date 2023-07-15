#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1421-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111081);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-9096", "CVE-2016-2339", "CVE-2016-7798", "CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");

  script_name(english:"Debian DLA-1421-1 : ruby2.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in the interpreter for the Ruby
language. The Common Vulnerabilities and Exposures project identifies
the following issues :

CVE-2015-9096

SMTP command injection in Net::SMTP via CRLF sequences in a RCPT TO or
MAIL FROM command.

CVE-2016-2339

Exploitable heap overflow in Fiddle::Function.new.

CVE-2016-7798

Incorrect handling of initialization vector in the GCM mode in the
OpenSSL extension.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf.

CVE-2017-0899

ANSI escape sequence vulnerability in RubyGems.

CVE-2017-0900

DoS vulnerability in the RubyGems query command.

CVE-2017-0901

gem installer allowed a malicious gem to overwrite arbitrary files.

CVE-2017-0902

RubyGems DNS request hijacking vulnerability.

CVE-2017-0903

Max Justicz reported that RubyGems is prone to an unsafe object
deserialization vulnerability. When parsed by an application which
processes gems, a specially crafted YAML formatted gem specification
can lead to remote code execution.

CVE-2017-10784

Yusuke Endoh discovered an escape sequence injection vulnerability in
the Basic authentication of WEBrick. An attacker can take advantage of
this flaw to inject malicious escape sequences to the WEBrick log and
potentially execute control characters on the victim's terminal
emulator when reading logs.

CVE-2017-14033

asac reported a buffer underrun vulnerability in the OpenSSL
extension. A remote attacker could take advantage of this flaw to
cause the Ruby interpreter to crash leading to a denial of service.

CVE-2017-14064

Heap memory disclosure in the JSON library.

CVE-2017-17405

A command injection vulnerability in Net::FTP might allow a malicious
FTP server to execute arbitrary commands.

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable
to an HTTP response splitting vulnerability. It was possible for an
attacker to inject fake HTTP responses if a script accepted an
external input and output it without modifications.

CVE-2017-17790

A command injection vulnerability in lib/resolv.rb's lazy_initialze
might allow a command injection attack. However untrusted input to
this function is rather unlikely.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the
Dir.mktmpdir method in the tmpdir library. It made it possible for
attackers to create arbitrary directories or files via a .. (dot dot)
in the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a
large request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby
String#unpack method. If a big number was passed with the specifier @,
the number was treated as a negative value, and an out-of-buffer read
occurred. Attackers could read data on heaps if an script accepts an
external input as the argument of String#unpack.

CVE-2018-8779

ooooooo_q reported that the UNIXServer.open and UNIXSocket.open
methods of the socket library bundled with Ruby did not check for NUL
bytes in the path argument. The lack of check made the methods
vulnerable to unintentional socket creation and unintentional socket
access.

CVE-2018-8780

ooooooo_q discovered an unintentional directory traversal in some
methods in Dir, by the lack of checking for NUL bytes in their
parameter.

CVE-2018-1000075

A negative size vulnerability in ruby gem package tar header that
could cause an infinite loop.

CVE-2018-1000076

RubyGems package improperly verifies cryptographic signatures. A
mis-signed gem could be installed if the tarball contains multiple gem
signatures.

CVE-2018-1000077

An improper input validation vulnerability in RubyGems specification
homepage attribute could allow malicious gem to set an invalid
homepage URL.

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of
homepage attribute.

CVE-2018-1000079

Path Traversal vulnerability during gem installation.

For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u4.

We recommend that you upgrade your ruby2.1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ruby2.1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libruby2.1", reference:"2.1.5-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1", reference:"2.1.5-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-dev", reference:"2.1.5-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-doc", reference:"2.1.5-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-tcltk", reference:"2.1.5-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
