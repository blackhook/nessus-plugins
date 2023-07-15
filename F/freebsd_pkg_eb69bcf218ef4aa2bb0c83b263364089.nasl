#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(108739);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2017-17742", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");

  script_name(english:"FreeBSD : ruby -- multiple vulnerabilities (eb69bcf2-18ef-4aa2-bb0c-83b263364089)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ruby news :

CVE-2017-17742: HTTP response splitting in WEBrick

If a script accepts an external input and outputs it without
modification as a part of HTTP responses, an attacker can use newline
characters to deceive the clients that the HTTP response header is
stopped at there, and can inject fake HTTP responses after the newline
characters to show malicious contents to the clients.

CVE-2018-6914: Unintentional file and directory creation with
directory traversal in tempfile and tmpdir

Dir.mktmpdir method introduced by tmpdir library accepts the prefix
and the suffix of the directory which is created as the first
parameter. The prefix can contain relative directory specifiers '../',
so this method can be used to target any directory. So, if a script
accepts an external input as the prefix, and the targeted directory
has inappropriate permissions or the ruby process has inappropriate
privileges, the attacker can create a directory or a file at any
directory.

CVE-2018-8777: DoS by large request in WEBrick

If an attacker sends a large request which contains huge HTTP headers,
WEBrick try to process it on memory, so the request causes the
out-of-memory DoS attack.

CVE-2018-8778: Buffer under-read in String#unpack

String#unpack receives format specifiers as its parameter, and can be
specified the position of parsing the data by the specifier @. If a
big number is passed with @, the number is treated as the negative
value, and out-of-buffer read is occurred. So, if a script accepts an
external input as the argument of String#unpack, the attacker can read
data on heaps.

CVE-2018-8779: Unintentional socket creation by poisoned NUL byte in
UNIXServer and UNIXSocket

UNIXServer.open accepts the path of the socket to be created at the
first parameter. If the path contains NUL (\0) bytes, this method
recognize that the path is completed before the NUL bytes. So, if a
script accepts an external input as the argument of this method, the
attacker can make the socket file in the unintentional path. And,
UNIXSocket.open also accepts the path of the socket to be created at
the first parameter without checking NUL bytes like UNIXServer.open.
So, if a script accepts an external input as the argument of this
method, the attacker can accepts the socket file in the unintentional
path.

CVE-2018-8780: Unintentional directory traversal by poisoned NUL byte
in Dir

Dir.open, Dir.new, Dir.entries and Dir.empty? accept the path of the
target directory as their parameter. If the parameter contains NUL
(\0) bytes, these methods recognize that the path is completed before
the NUL bytes. So, if a script accepts an external input as the
argument of these methods, the attacker can make the unintentional
directory traversal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2018/03/28/ruby-2-5-1-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2018/03/28/ruby-2-4-4-released/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ruby-lang.org/en/news/2018/03/28/ruby-2-3-7-released/"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/http-response-splitting-in-webrick-cve-2017-17742/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71079310"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/unintentional-file-and-directory-creation-with-directory-traversal-cve-2018-6914/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78bd7fa9"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/large-request-dos-in-webrick-cve-2018-8777/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4a4feab"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b770e41"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-unixsocket-cve-2018-8779/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95c4af25"
  );
  # https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-dir-cve-2018-8780/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23857932"
  );
  # https://vuxml.freebsd.org/freebsd/eb69bcf2-18ef-4aa2-bb0c-83b263364089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e3e020f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"ruby>=2.3.0,1<2.3.7,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.4.0,1<2.4.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby>=2.5.0,1<2.5.1,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
