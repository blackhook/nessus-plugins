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
  script_id(28193);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);

  script_name(english:"FreeBSD : xpdf -- multiple remote Stream.CC vulnerabilities (2747fc39-915b-11dc-9239-001c2514716c)");
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
"Secunia Research reports :

Secunia Research has discovered some vulnerabilities in Xpdf, which
can be exploited by malicious people to compromise a user's system.

- An array indexing error within the
'DCTStream::readProgressiveDataUnit()' method in xpdf/Stream.cc can be
exploited to corrupt memory via a specially crafted PDF file.

- An integer overflow error within the 'DCTStream::reset()' method in
xpdf/Stream.cc can be exploited to cause a heap-based buffer overflow
via a specially crafted PDF file.

- A boundary error within the 'CCITTFaxStream::lookChar()' method in
xpdf/Stream.cc can be exploited to cause a heap-based buffer overflow
by tricking a user into opening a PDF file containing a specially
crafted 'CCITTFaxDecode' filter.

Successful exploitation may allow execution of arbitrary code."
  );
  # https://vuxml.freebsd.org/freebsd/2747fc39-915b-11dc-9239-001c2514716c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90a76d19"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cups-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"cups-base<1.3.3_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gpdf>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"kdegraphics<3.5.8_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"koffice<1.6.3_3,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"poppler<0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xpdf<3.02_5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
