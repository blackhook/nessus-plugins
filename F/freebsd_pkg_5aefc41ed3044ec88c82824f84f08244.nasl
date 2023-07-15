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
  script_id(109661);
  script_version("1.10");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-5150", "CVE-2018-5151", "CVE-2018-5152", "CVE-2018-5153", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5165", "CVE-2018-5166", "CVE-2018-5167", "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173", "CVE-2018-5174", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177", "CVE-2018-5178", "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182", "CVE-2018-5183");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (5aefc41e-d304-4ec8-8c82-824f84f08244)");
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

CVE-2018-5183: Backport critical security fixes in Skia

CVE-2018-5154: Use-after-free with SVG animations and clip paths

CVE-2018-5155: Use-after-free with SVG animations and text paths

CVE-2018-5157: Same-origin bypass of PDF Viewer to view protected PDF
files

CVE-2018-5158: Malicious PDF can inject JavaScript into PDF Viewer

CVE-2018-5159: Integer overflow and out-of-bounds write in Skia

CVE-2018-5160: Uninitialized memory use by WebRTC encoder

CVE-2018-5152: WebExtensions information leak through webRequest API

CVE-2018-5153: Out-of-bounds read in mixed content websocket messages

CVE-2018-5163: Replacing cached data in JavaScript Start-up Bytecode
Cache

CVE-2018-5164: CSP not applied to all multipart content sent with
multipart/x-mixed-replace

CVE-2018-5166: WebExtension host permission bypass through
filterReponseData

CVE-2018-5167: Improper linkification of chrome: and javascript:
content in web console and JavaScript debugger

CVE-2018-5168: Lightweight themes can be installed without user
interaction

CVE-2018-5169: Dragging and dropping link text onto home button can
set home page to include chrome pages

CVE-2018-5172: Pasted script from clipboard can run in the Live
Bookmarks page or PDF viewer

CVE-2018-5173: File name spoofing of Downloads panel with Unicode
characters

CVE-2018-5174: Windows Defender SmartScreen UI runs with less secure
behavior for downloaded files in Windows 10 April 2018 Update

CVE-2018-5175: Universal CSP bypass on sites using strict-dynamic in
their policies

CVE-2018-5176: JSON Viewer script injection

CVE-2018-5177: Buffer overflow in XSLT during number formatting

CVE-2018-5165: Checkbox for enabling Flash protected mode is inverted
in 32-bit Firefox

CVE-2018-5178: Buffer overflow during UTF-8 to Unicode string
conversion through legacy extension

CVE-2018-5180: heap-use-after-free in
mozilla::WebGLContext::DrawElementsInstanced

CVE-2018-5181: Local file can be displayed in noopener tab through
drag and drop of hyperlink

CVE-2018-5182: Local file can be displayed from hyperlink dragged and
dropped on addressbar

CVE-2018-5151: Memory safety bugs fixed in Firefox 60

CVE-2018-5150: Memory safety bugs fixed in Firefox 60 and Firefox ESR
52.8"
  );
  # https://www.mozilla.org/security/advisories/mfsa2018-11/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-11/"
  );
  # https://www.mozilla.org/security/advisories/mfsa2018-12/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-12/"
  );
  # https://vuxml.freebsd.org/freebsd/5aefc41e-d304-4ec8-8c82-824f84f08244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc680ed0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/10");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<60.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.1.0_18")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.49.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.49.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<52.8.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<52.8.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<52.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<52.8.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<52.8.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
