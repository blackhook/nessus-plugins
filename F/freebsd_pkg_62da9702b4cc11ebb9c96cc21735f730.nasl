#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
include("compat.inc");

if (description)
{
  script_id(149512);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");
  script_xref(name:"IAVB", value:"2021-B-0036-S");

  script_name(english:"FreeBSD : PostgreSQL server -- two security issues (62da9702-b4cc-11eb-b9c9-6cc21735f730)");
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
"The PostgreSQL project reports :

Memory disclosure in INSERT ... ON CONFLICT ... DO UPDATE

Using an INSERT ... ON CONFLICT ... DO UPDATE command on a
purpose-crafted table, an attacker can read arbitrary bytes of server
memory. In the default configuration, any authenticated database user
can create prerequisite objects and complete this attack at will. A
user lacking the CREATE and TEMPORARY privileges on all databases and
the CREATE privilege on all schemas cannot use this attack at will..

Buffer overrun from integer overflow in array subscripting
calculations

While modifying certain SQL array values, missing bounds checks let
authenticated database users write arbitrary bytes to a wide area of
server memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/support/security/CVE-2021-32027/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/support/security/CVE-2021-32028/"
  );
  # https://vuxml.freebsd.org/freebsd/62da9702-b4cc-11eb-b9c9-6cc21735f730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5035bbcf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql13-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"postgresql13-server<13.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql12-server<12.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql11-server<11.12")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql10-server<10.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql96-server<9.6.22")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
