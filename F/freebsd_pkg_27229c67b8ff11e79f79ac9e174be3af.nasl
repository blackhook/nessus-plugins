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
  script_id(104162);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12607", "CVE-2017-12608", "CVE-2017-3157", "CVE-2017-9806");

  script_name(english:"FreeBSD : Apache OpenOffice -- multiple vulnerabilities (27229c67-b8ff-11e7-9f79-ac9e174be3af)");
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
"The Apache Openofffice project reports : CVE-2017-3157: Arbitrary file
disclosure in Calc and Writer By exploiting the way OpenOffice renders
embedded objects, an attacker could craft a document that allows
reading in a file from the user's filesystem. Information could be
retrieved by the attacker by, e.g., using hidden sections to store the
information, tricking the user into saving the document and convincing
the user to sent the document back to the attacker.

The vulnerability is mitigated by the need for the attacker to know
the precise file path in the target system, and the need to trick the
user into saving the document and sending it back. CVE-2017-9806:
Out-of-Bounds Write in Writer's WW8Fonts Constructor A vulnerability
in the OpenOffice Writer DOC file parser, and specifically in the
WW8Fonts Constructor, allows attackers to craft malicious documents
that cause denial of service (memory corruption and application crash)
potentially resulting in arbitrary code execution. CVE-2017-12607:
Out-of-Bounds Write in Impress' PPT Filter A vulnerability in
OpenOffice's PPT file parser, and specifically in PPTStyleSheet,
allows attackers to craft malicious documents that cause denial of
service (memory corruption and application crash) potentially
resulting in arbitrary code execution. CVE-2017-12608: Out-of-Bounds
Write in Writer's ImportOldFormatStyles A vulnerability in OpenOffice
Writer DOC file parser, and specifically in ImportOldFormatStyles,
allows attackers to craft malicious documents that cause denial of
service (memory corruption and application crash) potentially
resulting in arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openoffice.org/security/cves/CVE-2017-3157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openoffice.org/security/cves/CVE-2017-9806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openoffice.org/security/cves/CVE-2017-12607.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openoffice.org/security/cves/CVE-2017-12608.html"
  );
  # https://vuxml.freebsd.org/freebsd/27229c67-b8ff-11e7-9f79-ac9e174be3af.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f703ef76"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache-openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache-openoffice-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"apache-openoffice<4.1.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache-openoffice-devel<4.2.1810071_1,4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
