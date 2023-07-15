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
  script_id(34310);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
  script_bugtraq_id(31434);

  script_name(english:"FreeBSD : lighttpd -- multiple vulnerabilities (fb911e31-8ceb-11dd-bb29-000c6e274733)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Lighttpd seurity announcement :

lighttpd 1.4.19, and possibly other versions before 1.5.0, does not
decode the url before matching against rewrite and redirect patterns,
which allows attackers to bypass rewrites rules. this can be a
security problem in certain configurations if these rules are used to
hide certain urls.

lighttpd 1.4.19, and possibly other versions before 1.5.0, does not
lowercase the filename after generating it from the url in mod_userdir
on case insensitive (file)systems.

As other modules are case sensitive, this may lead to information
disclosure; for example if one configured php to handle files ending
on '.php', an attacker will get the php source with
http://example.com/~user/file.PHP

lighttpd 1.4.19 does not always release a header if it triggered a 400
(Bad Request) due to a duplicate header."
  );
  # http://www.lighttpd.net/security/lighttpd_sa_2008_05.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2008_05.txt"
  );
  # http://www.lighttpd.net/security/lighttpd_sa_2008_06.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2008_06.txt"
  );
  # http://www.lighttpd.net/security/lighttpd_sa_2008_07.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2008_07.txt"
  );
  # https://vuxml.freebsd.org/freebsd/fb911e31-8ceb-11dd-bb29-000c6e274733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc648025"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"lighttpd<1.4.19_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
