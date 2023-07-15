#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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
  script_id(128491);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2019-11734", "CVE-2019-11735", "CVE-2019-11736", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11741", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11751", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-5849", "CVE-2019-9812");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (05463e0a-abd3-4fa4-bd5f-cd5ed132d4c6)");
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

CVE-2019-11751: Malicious code execution through command line
parameters

CVE-2019-11746: Use-after-free while manipulating video

CVE-2019-11744: XSS by breaking out of title and textarea elements
using innerHTML

CVE-2019-11742: Same-origin policy violation with SVG filters and
canvas to steal cross-origin images

CVE-2019-11736: File manipulation and privilege escalation in Mozilla
Maintenance Service

CVE-2019-11753: Privilege escalation with Mozilla Maintenance Service
in custom Firefox installation location

CVE-2019-11752: Use-after-free while extracting a key value in
IndexedDB

CVE-2019-9812: Sandbox escape through Firefox Sync

CVE-2019-11741: Isolate addons.mozilla.org and accounts.firefox.com

CVE-2019-11743: Cross-origin access to unload event attributes

CVE-2019-11748: Persistence of WebRTC permissions in a third party
context

CVE-2019-11749: Camera information available without prompting using
getUserMedia

CVE-2019-5849: Out-of-bounds read in Skia

CVE-2019-11750: Type confusion in Spidermonkey

CVE-2019-11737: Content security policy directives ignore port and
path if host is a wildcard

CVE-2019-11738: Content security policy bypass through hash-based
sources in directives

CVE-2019-11747: 'Forget about this site' removes sites from pre-loaded
HSTS list

CVE-2019-11734: Memory safety bugs fixed in Firefox 69

CVE-2019-11735: Memory safety bugs fixed in Firefox 69 and Firefox ESR
68.1

CVE-2019-11740: Memory safety bugs fixed in Firefox 69, Firefox ESR
68.1, and Firefox ESR 60.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-25/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-27/"
  );
  # https://vuxml.freebsd.org/freebsd/05463e0a-abd3-4fa4-bd5f-cd5ed132d4c6.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3895b9cc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<69.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.2.14")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr>=61.0,1<68.1.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<60.9.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox>=61.0,2<68.1.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<60.9.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul>=61.0<68.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<60.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>=61.0<68.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<60.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird>=61.0<68.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<60.9.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
