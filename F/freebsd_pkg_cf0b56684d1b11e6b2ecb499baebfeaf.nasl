#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92395);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"FreeBSD : Multiple ports -- Proxy HTTP header vulnerability (httpoxy) (cf0b5668-4d1b-11e6-b2ec-b499baebfeaf)");
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
"httpoxy.org reports :

httpoxy is a set of vulnerabilities that affect application code
running in CGI, or CGI-like environments. It comes down to a simple
namespace conflict:.

- RFC 3875 (CGI) puts the HTTP Proxy header from a request into the
environment variables as HTTP_PROXY

- HTTP_PROXY is a popular environment variable used to configure an
outgoing proxy

This leads to a remotely exploitable vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://httpoxy.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kb.cert.org/vuls/id/797896"
  );
  # http://www.freebsd.org/ports/portaudit/cf0b5668-4d1b-11e6-b2ec-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2413f04a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-event-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-itk-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-peruser-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache22-worker-mpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tomcat8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"apache22<2.2.31_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-event-mpm<2.2.31_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-itk-mpm<2.2.31_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-peruser-mpm<2.2.31_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache22-worker-mpm<2.2.31_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache24<2.4.23_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tomcat6>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tomcat7>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tomcat8>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php55>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php56>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php70>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nginx>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"go<1.6.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"go14>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python27>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python33>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python34>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"python35>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"haproxy>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
