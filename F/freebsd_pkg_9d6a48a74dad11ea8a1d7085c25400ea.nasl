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
  script_id(133662);
  script_version("1.1");
  script_cvs_date("Date: 2020/02/13");

  script_name(english:"FreeBSD : grub2-bhyve -- multiple privilege escalations (9d6a48a7-4dad-11ea-8a1d-7085c25400ea)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Reno Robert reports :

FreeBSD uses a two-process model for running a VM. For booting
non-FreeBSD guests, a modified grub-emu is used (grub-bhyve).
Grub-bhyve executes command from guest grub.cfg file. This is a
security problem because grub was never written to handle inputs from
OS as untrusted. In the current design, grub and guest OS works across
trust boundaries. This exposes a grub to untrusted inputs from guest.

grub-bhyve (emu) is built without SDL graphics support which reduces
lot of gfx attack surface, however font loading code is still
accessible. Guest can provide arbitrary font file, which is parsed by
grub-bhyve running as root.

In grub-core/font/font.c, read_section_as_string() allocates
section->length + 1 bytes of memory. However, untrusted
section->length is an unsigned 32-bit number, and the result can
overflow to malloc(0). This can result in a controlled buffer overflow
via the 'loadfont' command in a guest VM grub2.cfg, eventually leading
to privilege escalation from guest to host.

Reno Robert also reports :

GRUB supports commands to read and write addresses of choice. In
grub-bhyve, these commands provide a way to write to arbitrary virtual
addresses within the grub-bhyve process. This is another way for a
guest grub2.cfg, run by the host, to eventually escalate privileges.

These vulnerabilities are mitigated by disabling the 'loadfont',
'write_dword', 'read_dword', 'inl', 'outl', and other width variants
of the same functionality in grub2-bhyve.

There is also work in progress to sandbox the grub-bhyve utility such
that an escaped guest ends up with nobody:nobody in a Capsium sandbox.
It is not included in 0.40_8."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.voidsecurity.in/"
  );
  # https://vuxml.freebsd.org/freebsd/9d6a48a7-4dad-11ea-8a1d-7085c25400ea.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50702284"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grub2-bhyve");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");
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

if (pkg_test(save_report:TRUE, pkg:"grub2-bhyve<0.40_8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
