#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(134686);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/19");

  script_name(english:"FreeBSD : www/py-bleach -- multiple vulnerabilities (3d19c776-68e7-11ea-91db-0050562a4d7b)");
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
"* ``bleach.clean`` behavior parsing embedded MathML and SVG content
with RCDATA tags did not match browser behavior and could result in a
mutation XSS.

Calls to ``bleach.clean`` with ``strip=False`` and ``math`` or ``svg``
tags and one or more of the RCDATA tags ``script``, ``noscript``,
``style``, ``noframes``, ``iframe``, ``noembed``, or ``xmp`` in the
allowed tags whitelist were vulnerable to a mutation XSS.

* ``bleach.clean`` behavior parsing ``noscript`` tags did not match
browser behavior.

Calls to ``bleach.clean`` allowing ``noscript`` and one or more of the
raw text tags (``title``, ``textarea``, ``script``, ``style``,
``noembed``, ``noframes``, ``iframe``, and ``xmp``) were vulnerable to
a mutation XSS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1615315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1621692"
  );
  # https://vuxml.freebsd.org/freebsd/3d19c776-68e7-11ea-91db-0050562a4d7b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcb3e506"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-bleach");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"py27-bleach<3.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-bleach<3.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-bleach<3.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-bleach<3.1.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-bleach<3.1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
