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
  script_id(19171);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"FreeBSD : mozilla -- privilege escalation via DOM property overrides (f650d5b8-ae62-11d9-a788-0001020eed82)");
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
"A Mozilla Foundation Security Advisory reports :

moz_bug_r_a4 reported several exploits giving an attacker the ability
to install malicious code or steal data, requiring only that the user
do commonplace actions like click on a link or open the context menu.
The common cause in each case was privileged UI code ('chrome') being
overly trusting of DOM nodes from the content window. Scripts in the
web page can override properties and methods of DOM nodes and shadow
the native values, unless steps are taken to get the true underlying
values.

We found that most extensions also interacted with content DOM in a
natural, but unsafe, manner. Changes were made so that chrome code
using this natural DOM coding style will now automatically use the
native DOM value if it exists without having to use cumbersome wrapper
objects.

Most of the specific exploits involved tricking the privileged code
into calling eval() on an attacker-supplied script string, or the
equivalent using the Script() object. Checks were added in the
security manager to make sure eval and Script objects are run with the
privileges of the context that created them, not the potentially
elevated privileges of the context calling them.

Workaround: Disable JavaScript"
  );
  # http://www.mozilla.org/security/announce/mfsa2005-41.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-41/"
  );
  # https://vuxml.freebsd.org/freebsd/f650d5b8-ae62-11d9-a788-0001020eed82.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8c8fce6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:el-linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-linux-mozillafirebird-gtk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-mozillafirebird-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-phoenix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phoenix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt_BR-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zhCN-linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zhTW-linux-mozillafirebird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<1.0.3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla<1.7.7,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla>=1.8.*,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla<1.7.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla>=1.8.*")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel<1.7.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel>=1.8.*")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netscape7>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"el-linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-linux-mozillafirebird-gtk1>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-mozillafirebird-gtk2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zhCN-linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zhTW-linux-mozillafirebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-netscape7>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-netscape7>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-netscape7>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-phoenix>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla+ipv6>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-embedded>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-firebird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk1>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-thunderbird>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"phoenix>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-netscape7>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
