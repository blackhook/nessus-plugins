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
  script_id(110254);
  script_version("1.11");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6128", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (427b0f58-644c-11e8-9e1b-e8e0b747a45a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

34 security fixes in this release, including :

- [835639] High CVE-2018-6123: Use after free in Blink. Reported by
Looben Yang on 2018-04-22

- [840320] High CVE-2018-6124: Type confusion in Blink. Reported by
Guang Gong of Alpha Team, Qihoo 360 on 2018-05-07

- [818592] High CVE-2018-6125: Overly permissive policy in WebUSB.
Reported by Yubico, Inc on 2018-03-05

- [844457] High CVE-2018-6126: Heap buffer overflow in Skia. Reported
by Ivan Fratric of Google Project Zero on 2018-05-18

- [842990] High CVE-2018-6127: Use after free in indexedDB. Reported
by Looben Yang on 2018-05-15

- [841105] High CVE-2018-6128: uXSS in Chrome on iOS. Reported by
Tomasz Bojarski on 2018-05-09

- [838672] High CVE-2018-6129: Out of bounds memory access in WebRTC.
Reported by Natalie Silvanovich of Google Project Zero on 2018-05-01

- [838402] High CVE-2018-6130: Out of bounds memory access in WebRTC.
Reported by Natalie Silvanovich of Google Project Zero on 2018-04-30

- [826434] High CVE-2018-6131: Incorrect mutability protection in
WebAssembly. Reported by Natalie Silvanovich of Google Project Zero on
2018-03-27

- [839960] Medium CVE-2018-6132: Use of uninitialized memory in
WebRTC. Reported by Ronald E. Crane on 2018-05-04

- [817247] Medium CVE-2018-6133: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-02-28

- [797465] Medium CVE-2018-6134: Referrer Policy bypass in Blink.
Reported by Jun Kokatsu (@shhnjk) on 2017-12-23

- [823353] Medium CVE-2018-6135: UI spoofing in Blink. Reported by
Jasper Rebane on 2018-03-19

- [831943] Medium CVE-2018-6136: Out of bounds memory access in V8.
Reported by Peter Wong on 2018-04-12

- [835589] Medium CVE-2018-6137: Leak of visited status of page in
Blink. Reported by Michael Smith (spinda.net) on 2018-04-21

- [810220] Medium CVE-2018-6138: Overly permissive policy in
Extensions. Reported by Francois Lajeunesse-Robert on 2018-02-08

- [805224] Medium CVE-2018-6139: Restrictions bypass in the debugger
extension API. Reported by Rob Wu on 2018-01-24

- [798222] Medium CVE-2018-6140: Restrictions bypass in the debugger
extension API. Reported by Rob Wu on 2018-01-01

- [796107] Medium CVE-2018-6141: Heap buffer overflow in Skia.
Reported by Yangkang (@dnpushme) and Wanglu of Qihoo360 Qex Team on
2017-12-19

- [837939] Medium CVE-2018-6142: Out of bounds memory access in V8.
Reported by Choongwoo Han of Naver Corporation on 2018-04-28

- [843022] Medium CVE-2018-6143: Out of bounds memory access in V8.
Reported by Guang Gong of Alpha Team, Qihoo 360 on 2018-05-15

- [828049] Low CVE-2018-6144: Out of bounds memory access in PDFium.
Reported by pdknsk on 2018-04-02

- [805924] Low CVE-2018-6145: Incorrect escaping of MathML in Blink.
Reported by Masato Kinugawa on 2018-01-25

- [818133] Low CVE-2018-6147: Password fields not taking advantage of
OS protections in Views. Reported by Michail Pishchagin (Yandex) on
2018-03-02

- [847542] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_58.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ac93e8"
  );
  # https://vuxml.freebsd.org/freebsd/427b0f58-644c-11e8-9e1b-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f447c183"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<67.0.3396.62")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
