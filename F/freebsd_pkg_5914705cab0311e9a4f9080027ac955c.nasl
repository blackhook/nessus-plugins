#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(126842);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_name(english:"FreeBSD : PuTTY 0.72 -- buffer overflow in SSH-1 and integer overflow in SSH client (5914705c-ab03-11e9-a4f9-080027ac955c)");
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
"Simon Tatham reports :

Vulnerabilities fixed in this release include :

- A malicious SSH-1 server could trigger a buffer overrun by sending
extremely short RSA keys, or certain bad packet length fields. Either
of these could happen before host key verification, so even if you
trust the server you *intended* to connect to, you would still be at
risk.

(However, the SSH-1 protocol is obsolete, and recent versions of PuTTY
do not try it by default, so you are only at risk if you work with old
servers and have explicitly configured SSH-1.)

- If a malicious process found a way to impersonate Pageant, then it
could cause an integer overflow in any of the SSH client tools (PuTTY,
Plink, PSCP, PSFTP) which accessed the malicious Pageant.

Other security-related bug fixes include :

- The 'trust sigil' system introduced in PuTTY 0.71 to protect against
server spoofing attacks had multiple bugs. Trust sigils were not
turned off after login in the SSH-1 and Rlogin protocols, and not
turned back on if you used the Restart Session command. Both are now
fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.tartarus.org/pipermail/putty-announce/2019/000028.html"
  );
  # https://vuxml.freebsd.org/freebsd/5914705c-ab03-11e9-a4f9-080027ac955c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6068d4da"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty-nogtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"putty<0.72")) flag++;
if (pkg_test(save_report:TRUE, pkg:"putty-gtk2<0.72")) flag++;
if (pkg_test(save_report:TRUE, pkg:"putty-nogtk<0.72")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
