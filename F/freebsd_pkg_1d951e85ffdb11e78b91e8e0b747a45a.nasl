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
  script_id(106236);
  script_version("3.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2017-15407", "CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15412", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15422", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427", "CVE-2017-15430");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (1d951e85-ffdb-11e7-8b91-e8e0b747a45a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

37 security fixes in this release, including :

- [778505] Critical CVE-2017-15407: Out of bounds write in QUIC.
Reported by Ned Williamson on 2017-10-26

- [762374] High CVE-2017-15408: Heap buffer overflow in PDFium.
Reported by Ke Liu of Tencent's Xuanwu LAB on 2017-09-06

- [763972] High CVE-2017-15409: Out of bounds write in Skia. Reported
by Anonymous on 2017-09-11

- [765921] High CVE-2017-15410: Use after free in PDFium. Reported by
Luat Nguyen of KeenLab, Tencent on 2017-09-16

- [770148] High CVE-2017-15411: Use after free in PDFium. Reported by
Luat Nguyen of KeenLab, Tencent on 2017-09-29

- [727039] High CVE-2017-15412: Use after free in libXML. Reported by
Nick Wellnhofer on 2017-05-27

- [766666] High CVE-2017-15413: Type confusion in WebAssembly.
Reported by Gaurav Dewan of Adobe Systems India Pvt. Ltd. on
2017-09-19

- [765512] Medium CVE-2017-15415: Pointer information disclosure in
IPC call. Reported by Viktor Brange of Microsoft Offensive Security
Research Team on 2017-09-15

- [779314] Medium CVE-2017-15416: Out of bounds read in Blink.
Reported by Ned Williamson on 2017-10-28

- [699028] Medium CVE-2017-15417: Cross origin information disclosure
in Skia. Reported by Max May on 2017-03-07

- [765858] Medium CVE-2017-15418: Use of uninitialized value in Skia.
Reported by Kushal Arvind Shah of Fortinet's FortiGuard Labs on
2017-09-15

- [780312] Medium CVE-2017-15419: Cross origin leak of redirect URL in
Blink. Reported by Jun Kokatsu on 2017-10-31

- [777419] Medium CVE-2017-15420: URL spoofing in Omnibox. Reported by
WenXu Wu of Tencent's Xuanwu Lab on 2017-10-23

- [774382] Medium CVE-2017-15422: Integer overflow in ICU. Reported by
Yuan Deng of Ant-financial Light-Year Security Lab on 2017-10-13

- [780484] Medium CVE-2017-15430: Unsafe navigation in Chromecast
Plugin. Reported by jinmo123 on 2017-01-11

- [778101] Low CVE-2017-15423: Issue with SPAKE implementation in
BoringSSL. Reported by Greg Hudson on 2017-10-25

- [756226] Low CVE-2017-15424: URL Spoof in Omnibox. Reported by
Khalil Zhani on 2017-08-16

- [756456] Low CVE-2017-15425: URL Spoof in Omnibox. Reported by
xisigr of Tencent's Xuanwu Lab on 2017-08-17

- [757735] Low CVE-2017-15426: URL Spoof in Omnibox. Reported by WenXu
Wu of Tencent's Xuanwu Lab on 2017-08-18

- [768910] Low CVE-2017-15427: Insufficient blocking of JavaScript in
Omnibox. Reported by Junaid Farhan on 2017-09-26

- [792099] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/12/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98a7b4bd"
  );
  # https://vuxml.freebsd.org/freebsd/1d951e85-ffdb-11e7-8b91-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5706b5c2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/23");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<63.0.3239.84")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
