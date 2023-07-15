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
  script_id(111179);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/10 11:49:47");

  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14362");

  script_name(english:"FreeBSD : mutt -- remote code injection and path traversal vulnerability (a2f35081-8a02-11e8-8fa5-4437e6ad11c4)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kevin J. McCarthy reports :

Fixes a remote code injection vulnerability when 'subscribing' to an
IMAP mailbox, either via $imap_check_subscribed, or via the
<subscribe> function in the browser menu. Mutt was generating a
'mailboxes' command and sending that along to the muttrc parser.
However, it was not escaping '`', which executes code and inserts the
result. This would allow a malicious IMAP server to execute arbitrary
code (for $imap_check_subscribed).

Fixes POP body caching path traversal vulnerability.

Fixes IMAP header caching path traversal vulnerability.

CVE-2018-14349 - NO Response Heap Overflow

CVE-2018-14350 - INTERNALDATE Stack Overflow

CVE-2018-14351 - STATUS Literal Length relative write

CVE-2018-14352 - imap_quote_string off-by-one stack overflow

CVE-2018-14353 - imap_quote_string int underflow

CVE-2018-14354 - imap_subscribe Remote Code Execution

CVE-2018-14355 - STATUS mailbox header cache directory traversal

CVE-2018-14356 - POP empty UID NULL deref

CVE-2018-14357 - LSUB Remote Code Execution

CVE-2018-14358 - RFC822.SIZE Stack Overflow

CVE-2018-14359 - base64 decode Stack Overflow

CVE-2018-14362 - POP Message Cache Directory Traversal"
  );
  # http://lists.mutt.org/pipermail/mutt-announce/Week-of-Mon-20180716/000004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2e0fc97"
  );
  # https://vuxml.freebsd.org/freebsd/a2f35081-8a02-11e8-8fa5-4437e6ad11c4.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cf1b892"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
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

if (pkg_test(save_report:TRUE, pkg:"mutt<1.10.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
