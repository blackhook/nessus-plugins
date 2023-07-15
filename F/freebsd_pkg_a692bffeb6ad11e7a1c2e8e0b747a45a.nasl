#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104063);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5130", "CVE-2017-5131", "CVE-2017-5132", "CVE-2017-5133");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a692bffe-b6ad-11e7-a1c2-e8e0b747a45a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

35 security fixes in this release, including :

- [762930] High CVE-2017-5124: UXSS with MHTML. Reported by Anonymous
on 2017-09-07

- [749147] High CVE-2017-5125: Heap overflow in Skia. Reported by
Anonymous on 2017-07-26

- [760455] High CVE-2017-5126: Use after free in PDFium. Reported by
Luat Nguyen on KeenLab, Tencent on 2017-08-30

- [765384] High CVE-2017-5127: Use after free in PDFium. Reported by
Luat Nguyen on KeenLab, Tencent on 2017-09-14

- [765469] High CVE-2017-5128: Heap overflow in WebGL. Reported by
Omair on 2017-09-14

- [765495] High CVE-2017-5129: Use after free in WebAudio. Reported by
Omair on 2017-09-15

- [718858] High CVE-2017-5132: Incorrect stack manipulation in
WebAssembly. Reported by Gaurav Dewan of Adobe Systems India Pvt. Ltd.
on 2017-05-05

- [722079] High CVE-2017-5130: Heap overflow in libxml2. Reported by
Pranjal Jumde on 2017-05-14

- [744109] Medium CVE-2017-5131: Out of bounds write in Skia. Reported
by Anonymous on 2017-07-16

- [762106] Medium CVE-2017-5133: Out of bounds write in Skia. Reported
by Aleksandar Nikolic of Cisco Talos on 2017-09-05

- [752003] Medium CVE-2017-15386: UI spoofing in Blink. Reported by
WenXu Wu of Tencent's Xuanwu Lab on 2017-08-03

- [756040] Medium CVE-2017-15387: Content security bypass. Reported by
Jun Kokatsu on 2017-08-16

- [756563] Medium CVE-2017-15388: Out of bounds read in Skia. Reported
by Kushal Arvind Shah of Fortinet's FortiGuard Labs on 2017-08-17

- [739621] Medium CVE-2017-15389: URL spoofing in Omnibox. Reported by
xisigr of Tencent's Xuanwu Lab on 2017-07-06

- [750239] Medium CVE-2017-15390: URL spoofing in Omnibox. Reported by
Haosheng Wang on 2017-07-28

- [598265] Low CVE-2017-15391: Extension limitation bypass in
Extensions. Reported by Joao Lucas Melo Brasio on 2016-03-28

- [714401] Low CVE-2017-15392: Incorrect registry key handling in
PlatformIntegration. Reported by Xiaoyin Liu on 2017-04-22

- [732751] Low CVE-2017-15393: Referrer leak in Devtools. Reported by
Svyat Mitin on 2017-06-13

- [745580] Low CVE-2017-15394: URL spoofing in extensions UI. Reported
by Sam on 2017-07-18

- [759457] Low CVE-2017-15395: NULL pointer dereference in
ImageCapture. Reported by Johannes Bergman on 2017-08-28

- [775550] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?441fea3d"
  );
  # https://vuxml.freebsd.org/freebsd/a692bffe-b6ad-11e7-a1c2-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1f39060"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<62.0.3202.62")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
