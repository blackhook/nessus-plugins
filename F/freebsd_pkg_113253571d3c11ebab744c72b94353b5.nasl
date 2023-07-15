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
  script_id(142311);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/03");

  script_name(english:"FreeBSD : wordpress -- multiple issues (11325357-1d3c-11eb-ab74-4c72b94353b5)");
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
"wordpress developers reports :

Ten security issues affect WordPress versions 5.5.1 and earlier. If
you havent yet updated to 5.5, all WordPress versions since 3.7 have
also been updated to fix the following security issues : -Props to
Alex Concha of the WordPress Security Team for their work in hardening
deserialization requests. -Props to David Binovec on a fix to disable
spam embeds from disabled sites on a multisite network. -Thanks to
Marc Montas from Sucuri for reporting an issue that could lead to XSS
from global variables. -Thanks to Justin Tran who reported an issue
surrounding privilege escalation in XML-RPC. He also found and
disclosed an issue around privilege escalation around post commenting
via XML-RPC. -Props to Omar Ganiev who reported a method where a DoS
attack could lead to RCE. -Thanks to Karim El Ouerghemmi from RIPS who
disclosed a method to store XSS in post slugs. -Thanks to Slavco for
reporting, and confirmation from Karim El Ouerghemmi, a method to
bypass protected meta that could lead to arbitrary file deletion."
  );
  # https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd17652d"
  );
  # https://vuxml.freebsd.org/freebsd/11325357-1d3c-11eb-ab74-4c72b94353b5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1ef4965"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh_CN-wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:zh_TW-wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");
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

if (pkg_test(save_report:TRUE, pkg:"wordpress<5.5.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-wordpress<5.5.2,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-wordpress<5.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh_CN-wordpress<5.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"zh_TW-wordpress<5.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-wordpress<5.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-wordpress<5.5.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
