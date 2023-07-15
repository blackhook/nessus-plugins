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
  script_id(111407);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6160", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (b9c525d9-9198-11e8-beba-080027ef1a23)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

42 security fixes in this release, including :

- [850350] High CVE-2018-6153: Stack buffer overflow in Skia. Reported
by Zhen Zhou of NSFOCUS Security Team on 2018-06-07

- [848914] High CVE-2018-6154: Heap buffer overflow in WebGL. Reported
by Omair on 2018-06-01

- [842265] High CVE-2018-6155: Use after free in WebRTC. Reported by
Natalie Silvanovich of Google Project Zero on 2018-05-11

- [841962] High CVE-2018-6156: Heap buffer overflow in WebRTC.
Reported by Natalie Silvanovich of Google Project Zero on 2018-05-10

- [840536] High CVE-2018-6157: Type confusion in WebRTC. Reported by
Natalie Silvanovich of Google Project Zero on 2018-05-07

- [812667] Medium CVE-2018-6150: Cross origin information disclosure
in Service Workers. Reported by Rob Wu on 2018-02-15

- [805905] Medium CVE-2018-6151: Bad cast in DevTools. Reported by Rob
Wu on 2018-01-25

- [805445] Medium CVE-2018-6152: Local file write in DevTools.
Reported by Rob Wu on 2018-01-24

- [841280] Medium CVE-2018-6158: Use after free in Blink. Reported by
Zhe Jin, Luyao Liu from Chengdu Security Response Center of Qihoo 360
Technology Co. Ltd on 2018-05-09

- [837275] Medium CVE-2018-6159: Same origin policy bypass in
ServiceWorker. Reported by Jun Kokatsu (@shhnjk) on 2018-04-26

- [839822] Medium CVE-2018-6160: URL spoof in Chrome on iOS. Reported
by evi1m0 of Bilibili Security Team on 2018-05-04

- [826552] Medium CVE-2018-6161: Same origin policy bypass in
WebAudio. Reported by Jun Kokatsu (@shhnjk) on 2018-03-27

- [804123] Medium CVE-2018-6162: Heap buffer overflow in WebGL.
Reported by Omair on 2018-01-21

- [849398] Medium CVE-2018-6163: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-06-04

- [848786] Medium CVE-2018-6164: Same origin policy bypass in
ServiceWorker. Reported by Jun Kokatsu (@shhnjk) on 2018-06-01

- [847718] Medium CVE-2018-6165: URL spoof in Omnibox. Reported by
evi1m0 of Bilibili Security Team on 2018-05-30

- [835554] Medium CVE-2018-6166: URL spoof in Omnibox. Reported by
Lnyas Zhang on 2018-04-21

- [833143] Medium CVE-2018-6167: URL spoof in Omnibox. Reported by
Lnyas Zhang on 2018-04-15

- [828265] Medium CVE-2018-6168: CORS bypass in Blink. Reported by
Gunes Acar and Danny Y. Huang of Princeton University, Frank Li of UC
Berkeley on 2018-04-03

- [394518] Medium CVE-2018-6169: Permissions bypass in extension
installation. Reported by Sam P on 2014-07-16

- [862059] Medium CVE-2018-6170: Type confusion in PDFium. Reported by
Anonymous on 2018-07-10

- [851799] Medium CVE-2018-6171: Use after free in WebBluetooth.
Reported by amazon@mimetics.ca on 2018-06-12

- [847242] Medium CVE-2018-6172: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-05-28

- [836885] Medium CVE-2018-6173: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-04-25

- [835299] Medium CVE-2018-6174: Integer overflow in SwiftShader.
Reported by Mark Brand of Google Project Zero on 2018-04-20

- [826019] Medium CVE-2018-6175: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-03-26

- [666824] Medium CVE-2018-6176: Local user privilege escalation in
Extensions. Reported by Jann Horn of Google Project Zero on 2016-11-18

- [826187] Low CVE-2018-6177: Cross origin information leak in Blink.
Reported by Ron Masas (Imperva) on 2018-03-27

- [823194] Low CVE-2018-6178: UI spoof in Extensions. Reported by
Khalil Zhani on 2018-03-19

- [816685] Low CVE-2018-6179: Local file information leak in
Extensions. Reported by Anonymous on 2018-02-26

- [797461] Low CVE-2018-6044: Request privilege escalation in
Extensions. Reported by Wob Wu on 2017-12-23

- [791324] Low CVE-2018-4117: Cross origin information leak in Blink.
Reported by AhsanEjaz - @AhsanEjazA on 2017-12-03

- [866821] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89d1144b"
  );
  # https://vuxml.freebsd.org/freebsd/b9c525d9-9198-11e8-beba-080027ef1a23.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47311ecc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<68.0.3440.75")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
