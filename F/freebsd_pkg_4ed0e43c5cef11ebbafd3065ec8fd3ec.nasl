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

include('compat.inc');

if (description)
{
  script_id(145316);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-16044",
    "CVE-2021-21117",
    "CVE-2021-21118",
    "CVE-2021-21119",
    "CVE-2021-21120",
    "CVE-2021-21121",
    "CVE-2021-21122",
    "CVE-2021-21123",
    "CVE-2021-21124",
    "CVE-2021-21125",
    "CVE-2021-21126",
    "CVE-2021-21127",
    "CVE-2021-21128",
    "CVE-2021-21129",
    "CVE-2021-21130",
    "CVE-2021-21131",
    "CVE-2021-21132",
    "CVE-2021-21133",
    "CVE-2021-21134",
    "CVE-2021-21135",
    "CVE-2021-21136",
    "CVE-2021-21137",
    "CVE-2021-21138",
    "CVE-2021-21139",
    "CVE-2021-21140",
    "CVE-2021-21141"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (4ed0e43c-5cef-11eb-bafd-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release contains 36 security fixes, including :

- [1137179] Critical CVE-2021-21117: Insufficient policy enforcement
in Cryptohome. Reported by Rory McNamara on 2020-10-10

- [1161357] High CVE-2021-21118: Insufficient data validation in V8.
Reported by Tyler Nighswander (@tylerni7) of Theori on 2020-12-23

- [1160534] High CVE-2021-21119: Use after free in Media. Reported by
Anonymous on 2020-12-20

- [1160602] High CVE-2021-21120: Use after free in WebSQL. Reported by
Nan Wang(@eternalsakura13) and Guang Gong of 360 Alpha Lab on
2020-12-21

- [1161143] High CVE-2021-21121: Use after free in Omnibox. Reported
by Leecraso and Guang Gong of 360 Alpha Lab on 2020-12-22

- [1162131] High CVE-2021-21122: Use after free in Blink. Reported by
Renata Hodovan on 2020-12-28

- [1137247] High CVE-2021-21123: Insufficient data validation in File
System API. Reported by Maciej Pulikowski on 2020-10-11

- [1131346] High CVE-2021-21124: Potential user after free in Speech
Recognizer. Reported by Chaoyang Ding(@V4kst1z) from Codesafe Team of
Legendsec at Qi'anxin Group on 2020-09-23

- [1152327] High CVE-2021-21125: Insufficient policy enforcement in
File System API. Reported by Ron Masas (Imperva) on 2020-11-24

- [1163228] High CVE-2020-16044: Use after free in WebRTC. Reported by
Ned Williamson of Project Zero on 2021-01-05

- [1108126] Medium CVE-2021-21126: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-07-22

- [1115590] Medium CVE-2021-21127: Insufficient policy enforcement in
extensions. Reported by Jasminder Pal Singh, Web Services Point WSP,
Kotkapura on 2020-08-12

- [1138877] Medium CVE-2021-21128: Heap buffer overflow in Blink.
Reported by Liang Dong on 2020-10-15

- [1140403] Medium CVE-2021-21129: Insufficient policy enforcement in
File System API. Reported by Maciej Pulikowski on 2020-10-20

- [1140410] Medium CVE-2021-21130: Insufficient policy enforcement in
File System API. Reported by Maciej Pulikowski on 2020-10-20

- [1140417] Medium CVE-2021-21131: Insufficient policy enforcement in
File System API. Reported by Maciej Pulikowski on 2020-10-20

- [1128206] Medium CVE-2021-21132: Inappropriate implementation in
DevTools. Reported by David Erceg on 2020-09-15

- [1157743] Medium CVE-2021-21133: Insufficient policy enforcement in
Downloads. Reported by wester0x01 (https://twitter.com/wester0x01) on
2020-12-11

- [1157800] Medium CVE-2021-21134: Incorrect security UI in Page Info.
Reported by wester0x01 (https://twitter.com/wester0x01) on 2020-12-11

- [1157818] Medium CVE-2021-21135: Inappropriate implementation in
Performance API. Reported by ndevtk on 2020-12-11

- [1038002] Low CVE-2021-21136: Insufficient policy enforcement in
WebView. Reported by Shiv Sahni, Movnavinothan V and Imdad Mohammed on
2019-12-27

- [1093791] Low CVE-2021-21137: Inappropriate implementation in
DevTools. Reported by bobblybear on 2020-06-11

- [1122487] Low CVE-2021-21138: Use after free in DevTools. Reported
by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at Qi'anxin
Group on 2020-08-27

- [1136327] Low CVE-2021-21140: Uninitialized Use in USB. Reported by
David Manouchehri on 2020-10-08

- [1140435] Low CVE-2021-21141: Insufficient policy enforcement in
File System API. Reported by Maciej Pulikowski on 2020-10-20");
  # https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ec68ce");
  # https://vuxml.freebsd.org/freebsd/4ed0e43c-5cef-11eb-bafd-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ab2f89a");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<88.0.4324.96")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
