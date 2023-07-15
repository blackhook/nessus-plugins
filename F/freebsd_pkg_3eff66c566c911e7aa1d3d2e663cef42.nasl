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
  script_id(101539);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_name(english:"FreeBSD : node.js -- multiple vulnerabilities (3eff66c5-66c9-11e7-aa1d-3d2e663cef42)");
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
"Updates are now available for all active Node.js release lines as well
as the 7.x line. These include the fix for the high severity
vulnerability identified in the initial announcement, one additional
lower priority Node.js vulnerability in the 4.x release line, as well
as some lower priority fixes for Node.js dependencies across the
current release lines. Constant Hashtable Seeds (CVE pending) Node.js
was susceptible to hash flooding remote DoS attacks as the HashTable
seed was constant across a given released version of Node.js. This was
a result of building with V8 snapshots enabled by default which caused
the initially randomized seed to be overwritten on startup. Thanks to
Jann Horn of Google Project Zero for reporting this vulnerability.

This is a high severity vulnerability and applies to all active
release lines (4.x, 6.x, 8.x) as well as the 7.x line. http.get with
numeric authorization options creates uninitialized buffers
Application code that allows the auth field of the options object used
with http.get() to be set to a number can result in an uninitialized
buffer being created/used as the authentication string.

This is a low severity defect and only applies to the 4.x release
line."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/vulnerability/july-2017-security-releases/"
  );
  # https://vuxml.freebsd.org/freebsd/3eff66c5-66c9-11e7-aa1d-3d2e663cef42.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33c353ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"node<8.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node4<4.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node6<6.11.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
