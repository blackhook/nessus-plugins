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
  script_id(111181);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363");

  script_name(english:"FreeBSD : mutt/neomutt -- multiple vulnerabilities (fe12ef83-8b47-11e8-96cc-001a4a7ec6be)");
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
"NeoMutt report : DescriptionCVE-2018-14349 NO Response Heap Overflow
CVE-2018-14350 INTERNALDATE Stack Overflow CVE-2018-14351 STATUS
Literal Length relative write CVE-2018-14352 imap_quote_string
off-by-one stack overflow CVE-2018-14353 imap_quote_string int
underflow CVE-2018-14354 imap_subscribe Remote Code Execution
CVE-2018-14355 STATUS mailbox header cache directory traversal
CVE-2018-14356 POP empty UID NULL deref CVE-2018-14357 LSUB Remote
Code Execution CVE-2018-14358 RFC822.SIZE Stack Overflow
CVE-2018-14359 base64 decode Stack Overflow CVE-2018-14360 NNTP Group
Stack Overflow CVE-2018-14361 NNTP Write 1 where via GROUP response
CVE-2018-14362 POP Message Cache Directory Traversal CVE-2018-14363
NNTP Header Cache Directory Traversal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/neomutt/neomutt/releases/tag/neomutt-20180716"
  );
  # https://vuxml.freebsd.org/freebsd/fe12ef83-8b47-11e8-96cc-001a4a7ec6be.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42a27674"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mutt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mutt14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:neomutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");
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

if (pkg_test(save_report:TRUE, pkg:"neomutt<20180716")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mutt<1.10.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mutt14<*")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
