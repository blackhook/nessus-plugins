#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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
  script_id(109877);
  script_version("1.5");
  script_cvs_date("Date: 2018/12/19 13:21:19");

  script_cve_id("CVE-2018-1000300", "CVE-2018-1000301");

  script_name(english:"FreeBSD : cURL -- multiple vulnerabilities (04fe6c8d-2a34-4009-a81e-e7a7e759b5d2)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cURL security problems :

CVE-2018-1000300: FTP shutdown response buffer overflow

curl might overflow a heap based memory buffer when closing down an
FTP connection with very long server command replies.

When doing FTP transfers, curl keeps a spare 'closure handle' around
internally that will be used when an FTP connection gets shut down
since the original curl easy handle is then already removed.

FTP server response data that gets cached from the original transfer
might then be larger than the default buffer size (16 KB) allocated in
the 'closure handle', which can lead to a buffer overwrite. The
contents and size of that overwrite is controllable by the server.

This situation was detected by an assert() in the code, but that was
of course only preventing bad stuff in debug builds. This bug is very
unlikely to trigger with non-malicious servers.

We are not aware of any exploit of this flaw.

CVE-2018-1000301: RTSP bad headers buffer over-read

curl can be tricked into reading data beyond the end of a heap based
buffer used to store downloaded content.

When servers send RTSP responses back to curl, the data starts out
with a set of headers. curl parses that data to separate it into a
number of headers to deal with those appropriately and to find the end
of the headers that signal the start of the 'body' part.

The function that splits up the response into headers is called
Curl_http_readwrite_headers() and in situations where it can't find a
single header in the buffer, it might end up leaving a pointer
pointing into the buffer instead of to the start of the buffer which
then later on may lead to an out of buffer read when code assumes that
pointer points to a full buffer size worth of memory to use.

This could potentially lead to information leakage but most likely a
crash/denial of service for applications if a server triggers this
flaw.

We are not aware of any exploit of this flaw."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/security.html"
  );
  # https://curl.haxx.se/docs/adv_2018-82c2.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2018-1000300.html"
  );
  # https://curl.haxx.se/docs/adv_2018-b138.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2018-1000301.html"
  );
  # https://vuxml.freebsd.org/freebsd/04fe6c8d-2a34-4009-a81e-e7a7e759b5d2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17f158f2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"curl<7.60.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
