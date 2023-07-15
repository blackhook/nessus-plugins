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
  script_id(106993);
  script_version("3.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-6871");

  script_name(english:"FreeBSD : LibreOffice -- Remote arbitrary file disclosure vulnerability via WEBSERVICE formula (289269f1-0def-11e8-99b0-d017c2987f9a)");
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
"LibreOffice reports :

LibreOffice Calc supports a WEBSERVICE function to obtain data by URL.
Vulnerable versions of LibreOffice allow WEBSERVICE to take a local
file URL (e.g file://) which can be used to inject local files into
the spreadsheet without warning the user. Subsequent formulas can
operate on that inserted data and construct a remote URL whose path
leaks the local data to a remote attacker.

In later versions of LibreOffice without this flaw, WEBSERVICE has now
been limited to accessing http and https URLs along with bringing
WEBSERVICE URLs under LibreOffice Calc's link management
infrastructure.

Note: This vulnerability has been identified upstream as
CVE-2018-1055, but NVD/Mitre are advising it's a reservation duplicate
of CVE-2018-6871 which should be used instead."
  );
  # https://www.libreoffice.org/about-us/security/advisories/cve-2018-1055/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8372621"
  );
  # https://github.com/jollheef/libreoffice-remote-arbitrary-file-disclosure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cc78a77"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=225797"
  );
  # https://vuxml.freebsd.org/freebsd/289269f1-0def-11e8-99b0-d017c2987f9a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6ea6a8b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libreoffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"libreoffice<5.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libreoffice>=6.0.0<6.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
