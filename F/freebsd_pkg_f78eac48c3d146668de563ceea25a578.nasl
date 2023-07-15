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
  script_id(104564);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7826", "CVE-2017-7827", "CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7831", "CVE-2017-7832", "CVE-2017-7833", "CVE-2017-7834", "CVE-2017-7835", "CVE-2017-7836", "CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7839", "CVE-2017-7840", "CVE-2017-7842");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (f78eac48-c3d1-4666-8de5-63ceea25a578)");
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
"Mozilla Foundation reports :

CVE-2017-7828: Use-after-free of PressShell while restyling layout

CVE-2017-7830: Cross-origin URL information leak through Resource
Timing API

CVE-2017-7831: Information disclosure of exposed properties on
JavaScript proxy objects

CVE-2017-7832: Domain spoofing through use of dotless 'i' character
followed by accent markers

CVE-2017-7833: Domain spoofing with Arabic and Indic vowel marker
characters

CVE-2017-7834: data: URLs opened in new tabs bypass CSP protections

CVE-2017-7835: Mixed content blocking incorrectly applies with
redirects

CVE-2017-7836: Pingsender dynamically loads libcurl on Linux and OS X

CVE-2017-7837: SVG loaded as <img> can use meta tags to set cookies

CVE-2017-7838: Failure of individual decoding of labels in
international domain names triggers punycode display of entire IDN

CVE-2017-7839: Control characters before javascript: URLs defeats
self-XSS prevention mechanism

CVE-2017-7840: Exported bookmarks do not strip script elements from
user-supplied tags

CVE-2017-7842: Referrer Policy is not always respected for <link>
elements

CVE-2017-7827: Memory safety bugs fixed in Firefox 57

CVE-2017-7826: Memory safety bugs fixed in Firefox 57 and Firefox ESR
52.5"
  );
  # https://www.mozilla.org/security/advisories/mfsa2017-24/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-24/"
  );
  # https://www.mozilla.org/security/advisories/mfsa2017-25/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-25/"
  );
  # https://vuxml.freebsd.org/freebsd/f78eac48-c3d1-4666-8de5-63ceea25a578.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d02b5e7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<56.0.2_10,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.49.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.49.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<52.5.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<52.5.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<52.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<52.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<52.5.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
