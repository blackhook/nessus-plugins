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
  script_id(18912);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1316");

  script_name(english:"FreeBSD : mozilla -- heap overflow in NNTP handler (3fbf9db2-658b-11d9-abad-000a95bc6fae)");
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
"Maurycy Prodeus reports a critical vulnerability in Mozilla-based
browsers :

Mozilla browser supports NNTP urls. Remote side is able to trigger
news:// connection to any server. I found a flaw in NNTP handling code
which may cause heap overflow and allow remote attacker to execute
arbitrary code on client machine."
  );
  # http://isec.pl/vulnerabilities/isec-0020-mozilla.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://isec.pl/en/vulnerabilities/isec-0020-mozilla.txt"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=110436284718949
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=bugtraq&m=110436284718949"
  );
  # https://vuxml.freebsd.org/freebsd/3fbf9db2-658b-11d9-abad-000a95bc6fae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc788a63"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:de-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:fr-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-netscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mozilla-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:netscape7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:pt_BR-netscape7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/13");
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

if (pkg_test(save_report:TRUE, pkg:"de-netscape7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-netscape7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-netscape7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"netscape7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"pt_BR-netscape7>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk1<1.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla<1.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-mozilla-devel<1.7.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla<1.7.5,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"de-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"fr-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-netscape>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla+ipv6>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-embedded>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk2>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mozilla-gtk>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
