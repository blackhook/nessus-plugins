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
  script_id(35990);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601");

  script_name(english:"FreeBSD : wireshark -- multiple vulnerabilities (f6f19735-9245-4918-8a60-87948ebb4907)");
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
"Vendor reports :

On non-Windows systems Wireshark could crash if the HOME environment
variable contained sprintf-style string formatting characters.
Wireshark could crash while reading a malformed NetScreen snoop file.
Wireshark could crash while reading a Tektronix K12 text capture file."
  );
  # http://www.wireshark.org/security/wnpa-sec-2009-01.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2009-01.html"
  );
  # https://vuxml.freebsd.org/freebsd/f6f19735-9245-4918-8a60-87948ebb4907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10d285bd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 119, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:tethereal-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:wireshark-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"ethereal<1.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ethereal-lite<1.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal<1.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"tethereal-lite<1.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark<1.0.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"wireshark-lite<1.0.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
