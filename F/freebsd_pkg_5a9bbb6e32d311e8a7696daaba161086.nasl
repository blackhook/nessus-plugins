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
  script_id(108738);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/10 11:49:46");

  script_cve_id("CVE-2018-7158", "CVE-2018-7159", "CVE-2018-7160");

  script_name(english:"FreeBSD : node.js -- multiple vulnerabilities (5a9bbb6e-32d3-11e8-a769-6daaba161086)");
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
"Node.js reports : Node.js Inspector DNS rebinding vulnerability
(CVE-2018-7160) Node.js 6.x and later include a debugger protocol
(also known as 'inspector') that can be activated by the --inspect and
related command line flags. This debugger service was vulnerable to a
DNS rebinding attack which could be exploited to perform remote code
execution. 'path' module regular expression denial of service
(CVE-2018-7158) The 'path' module in the Node.js 4.x release line
contains a potential regular expression denial of service (ReDoS)
vector. The code in question was replaced in Node.js 6.x and later so
this vulnerability only impacts all versions of Node.js 4.x. Spaces in
HTTP Content-Length header values are ignored (CVE-2018-7159) The HTTP
parser in all current versions of Node.js ignores spaces in the
Content-Length header, allowing input such as Content-Length: 1 2 to
be interpreted as having a value of 12. The HTTP specification does
not allow for spaces in the Content-Length value and the Node.js HTTP
parser has been brought into line on this particular difference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/vulnerability/march-2018-security-releases/"
  );
  # https://vuxml.freebsd.org/freebsd/5a9bbb6e-32d3-11e8-a769-6daaba161086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f65da06c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");
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

if (pkg_test(save_report:TRUE, pkg:"node4<4.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node6<6.14.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.11.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<9.10.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
