#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
  script_id(144823);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2020-15995", "CVE-2020-16043", "CVE-2021-21106", "CVE-2021-21107", "CVE-2021-21108", "CVE-2021-21109", "CVE-2021-21110", "CVE-2021-21111", "CVE-2021-21112", "CVE-2021-21113", "CVE-2021-21114", "CVE-2021-21115", "CVE-2021-21116");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (d153c4d2-50f8-11eb-8046-3065ec8fd3ec)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This release includes 16 security fixes, including :

- [1148749] High CVE-2021-21106: Use after free in autofill. Reported
by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at Qi'anxin
Group on 2020-11-13

- [1153595] High CVE-2021-21107: Use after free in drag and drop.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2020-11-30

- [1155426] High CVE-2021-21108: Use after free in media. Reported by
Leecraso and Guang Gong of 360 Alpha Lab on 2020-12-04

- [1152334] High CVE-2021-21109: Use after free in payments. Reported
by Rong Jian and Guang Gong of 360 Alpha Lab on 2020-11-24

- [1152451] High CVE-2021-21110: Use after free in safe browsing.
Reported by Anonymous on 2020-11-24

- [1149125] High CVE-2021-21111: Insufficient policy enforcement in
WebUI. Reported by Alesandro Ortiz on 2020-11-15

- [1151298] High CVE-2021-21112: Use after free in Blink. Reported by
YoungJoo Lee(@ashuu_lee) of Raon Whitehat on 2020-11-20

- [1155178] High CVE-2021-21113: Heap buffer overflow in Skia.
Reported by tsubmunu on 2020-12-03

- [1148309] High CVE-2020-16043: Insufficient data validation in
networking. Reported by Samy Kamkar, Ben Seri at Armis, Gregory
Vishnepolsky at Armis on 2020-11-12

- [1150065] High CVE-2021-21114: Use after free in audio. Reported by
Man Yue Mo of GitHub Security Lab on 2020-11-17

- [1157790] High CVE-2020-15995: Out of bounds write in V8. Reported
by Bohan Liu (@P4nda20371774) of Tencent Security Xuanwu Lab on
2020-12-11

- [1157814] High CVE-2021-21115: Use after free in safe browsing.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2020-12-11

- [1151069] Medium CVE-2021-21116: Heap buffer overflow in audio.
Reported by Alison Huffman, Microsoft Browser Vulnerability Research
on 2020-11-19"
  );
  # https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c62eaf91"
  );
  # https://vuxml.freebsd.org/freebsd/d153c4d2-50f8-11eb-8046-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c29eed5f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21106");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<87.0.4280.141")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
