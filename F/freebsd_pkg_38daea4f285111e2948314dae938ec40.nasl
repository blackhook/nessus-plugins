#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62832);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (38daea4f-2851-11e2-9483-14dae938ec40)");
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
"Opera reports :

CORS (Cross-Origin Resource Sharing) allows web pages to retrieve the
contents of pages from other sites, with their permission, as they
would appear for the current user. When requests are made in this way,
the browser should only allow the page content to be retrieved if the
target site sends the correct headers that give permission for their
contents to be used in this way. Specially crafted requests may trick
Opera into thinking that the target site has given permission when it
had not done so. This can result in the contents of any target page
being revealed to untrusted sites, including any sensitive information
or session IDs contained within the source of those pages.

Also reported are vulnerabilities involving SVG graphics and XSS."
  );
  # http://www.opera.com/support/kb/view/1030/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d96af00"
  );
  # http://www.opera.com/support/kb/view/1031/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61043652"
  );
  # http://www.opera.com/support/kb/view/1033/
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.opera.com/"
  );
  # https://vuxml.freebsd.org/freebsd/38daea4f-2851-11e2-9483-14dae938ec40.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a45e9775"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<12.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"opera-devel<12.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<12.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera-devel<12.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
