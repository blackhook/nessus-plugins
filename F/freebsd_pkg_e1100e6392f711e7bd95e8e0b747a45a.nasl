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
  script_id(102988);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", "CVE-2017-5119", "CVE-2017-5120");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (e1100e63-92f7-11e7-bd95-e8e0b747a45a)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome releases reports :

22 security fixes in this release, including :

- [737023] High CVE-2017-5111: Use after free in PDFium. Reported by
Luat Nguyen on KeenLab, Tencent on 2017-06-27

- [740603] High CVE-2017-5112: Heap buffer overflow in WebGL. Reported
by Tobias Klein on 2017-07-10

- [747043] High CVE-2017-5113: Heap buffer overflow in Skia. Reported
by Anonymous on 2017-07-20

- [752829] High CVE-2017-5114: Memory life cycle issue in PDFium.
Reported by Ke Liu of Tencent's Xuanwu LAB on 2017-08-07

- [744584] High CVE-2017-5115: Type confusion in V8. Reported by Marco
Giovannini on 2017-07-17

- [759624] High CVE-2017-5116: Type confusion in V8. Reported by
Anonymous on 2017-08-28

- [739190] Medium CVE-2017-5117: Use of uninitialized value in Skia.
Reported by Tobias Klein on 2017-07-04

- [747847] Medium CVE-2017-5118: Bypass of Content Security Policy in
Blink. Reported by WenXu Wu of Tencent's Xuanwu Lab on 2017-07-24

- [725127] Medium CVE-2017-5119: Use of uninitialized value in Skia.
Reported by Anonymous on 2017-05-22

- [718676] Low CVE-2017-5120: Potential HTTPS downgrade during
redirect navigation. Reported by Xiaoyin Liu on 2017-05-05

- [762099] Various fixes from internal audits, fuzzing and other
initiatives"
  );
  # https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67b28931"
  );
  # https://vuxml.freebsd.org/freebsd/e1100e63-92f7-11e7-bd95-e8e0b747a45a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2df7936"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/07");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<61.0.3163.79")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
