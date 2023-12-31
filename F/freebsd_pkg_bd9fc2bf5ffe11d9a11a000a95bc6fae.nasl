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
  script_id(19103);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-1138");

  script_name(english:"FreeBSD : vim -- vulnerabilities in modeline handling (bd9fc2bf-5ffe-11d9-a11a-000a95bc6fae)");
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
"Ciaran McCreesh discovered news ways in which a VIM modeline can be
used to trojan a text file. The patch by Bram Moolenaar reads :

Problem: Unusual characters in an option value may cause unexpected
behavior, especially for a modeline. (Ciaran McCreesh)

Solution: Don't allow setting termcap options or 'printdevice' or
'titleold' in a modeline. Don't list options for 'termcap' and 'all'
in a modeline. Don't allow unusual characters in 'filetype', 'syntax',
'backupext', 'keymap', 'patchmode' and 'langmenu'.

Note: It is generally recommended that VIM users use set nomodeline in
~/.vimrc to avoid the possibility of trojaned text files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"ftp://ftp.vim.org/pub/vim/patches/6.3/6.3.045"
  );
  # http://groups.yahoo.com/group/vimdev/message/38084
  script_set_attribute(
    attribute:"see_also",
    value:"https://groups.yahoo.com/neo/groups/vimdev/conversations/topics/38084"
  );
  # https://vuxml.freebsd.org/freebsd/bd9fc2bf-5ffe-11d9-a11a-000a95bc6fae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?366c1758"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim+ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:vim-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
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

if (pkg_test(save_report:TRUE, pkg:"vim<6.3.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim-console<6.3.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim-lite<6.3.45")) flag++;
if (pkg_test(save_report:TRUE, pkg:"vim+ruby<6.3.45")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
