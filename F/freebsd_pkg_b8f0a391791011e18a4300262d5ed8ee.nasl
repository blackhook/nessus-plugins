#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(58521);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2011-3057", "CVE-2011-3058", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3061", "CVE-2011-3062", "CVE-2011-3063", "CVE-2011-3064", "CVE-2011-3065");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (b8f0a391-7910-11e1-8a43-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

[109574] Medium CVE-2011-3058: Bad interaction possibly leading to XSS
in EUC-JP. Credit to Masato Kinugawa.

[112317] Medium CVE-2011-3059: Out-of-bounds read in SVG text
handling. Credit to Arthur Gerkis.

[114056] Medium CVE-2011-3060: Out-of-bounds read in text fragment
handling. Credit to miaubiz.

[116398] Medium CVE-2011-3061: SPDY proxy certificate checking error.
Credit to Leonidas Kontothanassis of Google.

[116524] High CVE-2011-3062: Off-by-one in OpenType Sanitizer. Credit
to Mateusz Jurczyk of the Google Security Team.

[117417] Low CVE-2011-3063: Validate navigation requests from the
renderer more carefully. Credit to kuzzcc, Sergey Glazunov, PinkiePie
and scarybeasts (Google Chrome Security Team).

[117471] High CVE-2011-3064: Use-after-free in SVG clipping. Credit to
Atte Kettunen of OUSPG.

[117588] High CVE-2011-3065: Memory corruption in Skia. Credit to
Omair.

[117794] Medium CVE-2011-3057: Invalid read in v8. Credit to Christian
Holler."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/b8f0a391-7910-11e1-8a43-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de57180b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<18.0.1025.142")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
