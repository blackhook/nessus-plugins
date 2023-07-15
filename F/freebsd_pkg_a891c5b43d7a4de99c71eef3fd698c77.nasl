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
  script_id(106288);
  script_version("3.11");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-5089", "CVE-2018-5090", "CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094", "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107", "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5110", "CVE-2018-5111", "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115", "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5118", "CVE-2018-5119", "CVE-2018-5121", "CVE-2018-5122");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (a891c5b4-3d7a-4de9-9c71-eef3fd698c77)");
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

CVE-2018-5091: Use-after-free with DTMF timers

CVE-2018-5092: Use-after-free in Web Workers

CVE-2018-5093: Buffer overflow in WebAssembly during Memory/Table
resizing

CVE-2018-5094: Buffer overflow in WebAssembly with garbage collection
on uninitialized memory

CVE-2018-5095: Integer overflow in Skia library during edge builder
allocation

CVE-2018-5097: Use-after-free when source document is manipulated
during XSLT

CVE-2018-5098: Use-after-free while manipulating form input elements

CVE-2018-5099: Use-after-free with widget listener

CVE-2018-5100: Use-after-free when IsPotentiallyScrollable arguments
are freed from memory

CVE-2018-5101: Use-after-free with floating first-letter style
elements

CVE-2018-5102: Use-after-free in HTML media elements

CVE-2018-5103: Use-after-free during mouse event handling

CVE-2018-5104: Use-after-free during font face manipulation

CVE-2018-5105: WebExtensions can save and execute files on local file
system without user prompts

CVE-2018-5106: Developer Tools can expose style editor information
cross-origin through service worker

CVE-2018-5107: Printing process will follow symlinks for local file
access

CVE-2018-5108: Manually entered blob URL can be accessed by subsequent
private browsing tabs

CVE-2018-5109: Audio capture prompts and starts with incorrect origin
attribution

CVE-2018-5110: Cursor can be made invisible on OS X

CVE-2018-5111: URL spoofing in addressbar through drag and drop

CVE-2018-5112: Extension development tools panel can open a
non-relative URL in the panel

CVE-2018-5113: WebExtensions can load non-HTTPS pages with
browser.identity.launchWebAuthFlow

CVE-2018-5114: The old value of a cookie changed to HttpOnly remains
accessible to scripts

CVE-2018-5115: Background network requests can open HTTP
authentication in unrelated foreground tabs

CVE-2018-5116: WebExtension ActiveTab permission allows cross-origin
frame content access

CVE-2018-5117: URL spoofing with right-to-left text aligned
left-to-right

CVE-2018-5118: Activity Stream images can attempt to load local
content through file :

CVE-2018-5119: Reader view will load cross-origin content in violation
of CORS headers

CVE-2018-5121: OS X Tibetan characters render incompletely in the
addressbar

CVE-2018-5122: Potential integer overflow in DoCrypt

CVE-2018-5090: Memory safety bugs fixed in Firefox 58

CVE-2018-5089: Memory safety bugs fixed in Firefox 58 and Firefox ESR
52.6"
  );
  # https://www.mozilla.org/security/advisories/mfsa2018-02/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/"
  );
  # https://www.mozilla.org/security/advisories/mfsa2018-03/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-03/"
  );
  # https://vuxml.freebsd.org/freebsd/a891c5b4-3d7a-4de9-9c71-eef3fd698c77.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a44141c"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:waterfox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<58.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.0.3.63")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.49.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.49.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<52.6.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<52.6.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<52.6.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<52.6.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<52.6.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
