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
  script_id(119511);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-0734", "CVE-2018-0735", "CVE-2018-12116", "CVE-2018-12120", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-5407");

  script_name(english:"FreeBSD : node.js -- multiple vulnerabilities (2a86f45a-fc3c-11e8-a414-00155d006b02)");
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
"Node.js reports :

Updates are now available for all active Node.js release lines. These
include fixes for the vulnerabilities identified in the initial
announcement. They also include upgrades of Node.js 6 and 8 to OpenSSL
1.0.2q, and upgrades of Node.js 10 and 11 to OpenSSL 1.1.0j.

We recommend that all Node.js users upgrade to a version listed below
as soon as possible. Debugger port 5858 listens on any interface by
default (CVE-2018-12120) All versions of Node.js 6 are vulnerable and
the severity is HIGH. When the debugger is enabled with node --debug
or node debug, it listens to port 5858 on all interfaces by default.
This may allow remote computers to attach to the debug port and
evaluate arbitrary JavaScript. The default interface is now localhost.
It has always been possible to start the debugger on a specific
interface, such as node --debug=localhost. The debugger was removed in
Node.js 8 and replaced with the inspector, so no versions from 8 and
later are vulnerable. Denial of Service with large HTTP headers
(CVE-2018-12121) All versions of 6 and later are vulnerable and the
severity is HIGH. By using a combination of many requests with maximum
sized headers (almost 80 KB per connection), and carefully timed
completion of the headers, it is possible to cause the HTTP server to
abort from heap allocation failure. Attack potential is mitigated by
the use of a load balancer or other proxy layer.

The total size of HTTP headers received by Node.js now must not exceed
8192 bytes. 'Slowloris' HTTP Denial of Service (CVE-2018-12122) All
versions of Node.js 6 and later are vulnerable and the severity is
LOW. An attacker can cause a Denial of Service (DoS) by sending
headers very slowly keeping HTTP or HTTPS connections and associated
resources alive for a long period of time. Attack potential is
mitigated by the use of a load balancer or other proxy layer.

A timeout of 40 seconds now applies to servers receiving HTTP headers.
This value can be adjusted with server.headersTimeout. Where headers
are not completely received within this period, the socket is
destroyed on the next received chunk. In conjunction with
server.setTimeout(), this aids in protecting against excessive
resource retention and possible Denial of Service. Hostname spoofing
in URL parser for JavaScript protocol (CVE-2018-12123) All versions of
Node.js 6 and later are vulnerable and the severity is LOW. If a
Node.js application is using url.parse() to determine the URL
hostname, that hostname can be spoofed by using a mixed case
'javascript:' (e.g. 'javAscript:') protocol (other protocols are not
affected). If security decisions are made about the URL based on the
hostname, they may be incorrect. HTTP request splitting
(CVE-2018-12116) Node.js 6 and 8 are vulnerable and the severity is
MEDIUM. If Node.js can be convinced to use unsanitized user-provided
Unicode data for the path option of an HTTP request, then data can be
provided which will trigger a second, unexpected, and user-defined
HTTP request to made to the same server. OpenSSL Timing vulnerability
in ECDSA signature generation (CVE-2018-0735) The OpenSSL ECDSA
signature algorithm has been shown to be vulnerable to a timing
side-channel attack. An attacker could use variations in the signing
algorithm to recover the private key. OpenSSL Timing vulnerability in
DSA signature generation (CVE-2018-0734) The OpenSSL DSA signature
algorithm has been shown to be vulnerable to a timing side-channel
attack. An attacker could use variations in the signing algorithm to
recover the private key. OpenSSL Microarchitecture timing
vulnerability in ECC scalar multiplication (CVE-2018-5407) OpenSSL ECC
scalar multiplication, used in e.g. ECDSA and ECDH, has been shown to
be vulnerable to a microarchitecture timing side-channel attack. An
attacker with sufficient access to mount local timing attacks during
ECDSA signature generation could recover the private key."
  );
  # https://nodejs.org/en/blog/vulnerability/november-2018-security-releases/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdc3667d"
  );
  # https://vuxml.freebsd.org/freebsd/2a86f45a-fc3c-11e8-a414-00155d006b02.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?721f1cad"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");
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

if (pkg_test(save_report:TRUE, pkg:"node6<6.15.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.14.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node10<10.14.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<11.3.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
