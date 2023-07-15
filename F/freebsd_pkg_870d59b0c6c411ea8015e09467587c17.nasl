#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(138537);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-6510",
    "CVE-2020-6511",
    "CVE-2020-6512",
    "CVE-2020-6513",
    "CVE-2020-6514",
    "CVE-2020-6515",
    "CVE-2020-6516",
    "CVE-2020-6517",
    "CVE-2020-6518",
    "CVE-2020-6519",
    "CVE-2020-6520",
    "CVE-2020-6521",
    "CVE-2020-6522",
    "CVE-2020-6523",
    "CVE-2020-6524",
    "CVE-2020-6525",
    "CVE-2020-6526",
    "CVE-2020-6527",
    "CVE-2020-6528",
    "CVE-2020-6529",
    "CVE-2020-6530",
    "CVE-2020-6531",
    "CVE-2020-6533",
    "CVE-2020-6534",
    "CVE-2020-6535",
    "CVE-2020-6536"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (870d59b0-c6c4-11ea-8015-e09467587c17)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This update contains 38 security fixes, including :

- [1103195] Critical CVE-2020-6510: Heap buffer overflow in background
fetch. Reported by Leecraso and Guang Gong of 360 Alpha Lab working
with 360 BugCloud on 2020-07-08

- [1074317] High CVE-2020-6511: Side-channel information leakage in
content security policy. Reported by Mikhail Oblozhikhin on 2020-04-24

- [1084820] High CVE-2020-6512: Type Confusion in V8. Reported by
nocma, leogan, cheneyxu of WeChat Open Platform Security Team on
2020-05-20

- [1091404] High CVE-2020-6513: Heap buffer overflow in PDFium.
Reported by Aleksandar Nikolic of Cisco Talos on 2020-06-04

- [1076703] High CVE-2020-6514: Inappropriate implementation in
WebRTC. Reported by Natalie Silvanovich of Google Project Zero on
2020-04-30

- [1082755] High CVE-2020-6515: Use after free in tab strip. Reported
by DDV_UA on 2020-05-14

- [1092449] High CVE-2020-6516: Policy bypass in CORS. Reported by
Yongke Wang(@Rudykewang) and Aryb1n(@aryb1n) of Tencent Security
Xuanwu Lab on 2020-06-08

- [1095560] High CVE-2020-6517: Heap buffer overflow in history.
Reported by ZeKai Wu (@hellowuzekai) of Tencent Security Xuanwu Lab on
2020-06-16

- [986051] Medium CVE-2020-6518: Use after free in developer tools.
Reported by David Erceg on 2019-07-20

- [1064676] Medium CVE-2020-6519: Policy bypass in CSP. Reported by
Gal Weizman (@WeizmanGal) of PerimeterX on 2020-03-25

- [1092274] Medium CVE-2020-6520: Heap buffer overflow in Skia.
Reported by Zhen Zhou of NSFOCUS Security Team on 2020-06-08

- [1075734] Medium CVE-2020-6521: Side-channel information leakage in
autofill. Reported by Xu Lin (University of Illinois at Chicago),
Panagiotis Ilia (University of Illinois at Chicago), Jason Polakis
(University of Illinois at Chicago) on 2020-04-27

- [1052093] Medium CVE-2020-6522: Inappropriate implementation in
external protocol handlers. Reported by Eric Lawrence of Microsoft on
2020-02-13

- [1080481] Medium CVE-2020-6523: Out of bounds write in Skia.
Reported by Liu Wei and Wu Zekai of Tencent Security Xuanwu Lab on
2020-05-08

- [1081722] Medium CVE-2020-6524: Heap buffer overflow in WebAudio.
Reported by Sung Ta (@Mipu94) of SEFCOM Lab, Arizona State University
on 2020-05-12

- [1091670] Medium CVE-2020-6525: Heap buffer overflow in Skia.
Reported by Zhen Zhou of NSFOCUS Security Team on 2020-06-05

- [1074340] Low CVE-2020-6526: Inappropriate implementation in iframe
sandbox. Reported by Jonathan Kingston on 2020-04-24

- [992698] Low CVE-2020-6527: Insufficient policy enforcement in CSP.
Reported by Zhong Zhaochen of andsecurity.cn on 2019-08-10

- [1063690] Low CVE-2020-6528: Incorrect security UI in basic auth.
Reported by Rayyan Bijoora on 2020-03-22

- [978779] Low CVE-2020-6529: Inappropriate implementation in WebRTC.
Reported by kaustubhvats7 on 2019-06-26

- [1016278] Low CVE-2020-6530: Out of bounds memory access in
developer tools. Reported by myvyang on 2019-10-21

- [1042986] Low CVE-2020-6531: Side-channel information leakage in
scroll to text. Reported by Jun Kokatsu, Microsoft Browser
Vulnerability Research on 2020-01-17

- [1069964] Low CVE-2020-6533: Type Confusion in V8. Reported by
Avihay Cohen @ SeraphicAlgorithms on 2020-04-11

- [1072412] Low CVE-2020-6534: Heap buffer overflow in WebRTC.
Reported by Anonymous on 2020-04-20

- [1073409] Low CVE-2020-6535: Insufficient data validation in WebUI.
Reported by Jun Kokatsu, Microsoft Browser Vulnerability Research on
2020-04-22

- [1080934] Low CVE-2020-6536: Incorrect security UI in PWAs. Reported
by Zhiyang Zeng of Tencent security platform department on 2020-05-09");
  # https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96792814");
  # https://vuxml.freebsd.org/freebsd/870d59b0-c6c4-11ea-8015-e09467587c17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?409aa410");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6522");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<84.0.4147.89")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
