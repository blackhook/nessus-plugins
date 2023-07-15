#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151972);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-30565",
    "CVE-2021-30566",
    "CVE-2021-30567",
    "CVE-2021-30568",
    "CVE-2021-30569",
    "CVE-2021-30571",
    "CVE-2021-30572",
    "CVE-2021-30573",
    "CVE-2021-30574",
    "CVE-2021-30575",
    "CVE-2021-30576",
    "CVE-2021-30577",
    "CVE-2021-30578",
    "CVE-2021-30579",
    "CVE-2021-30580",
    "CVE-2021-30581",
    "CVE-2021-30582",
    "CVE-2021-30583",
    "CVE-2021-30584",
    "CVE-2021-30585",
    "CVE-2021-30586",
    "CVE-2021-30587",
    "CVE-2021-30588",
    "CVE-2021-30589"
  );
  script_xref(name:"IAVA", value:"2021-A-0346-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (76487640-ea29-11eb-a686-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release contains 35 security fixes, including :

- ][1210985] High CVE-2021-30565: Out of bounds write in Tab Groups.
Reported by David Erceg on 2021-05-19

- [1202661] High CVE-2021-30566: Stack buffer overflow in Printing.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2021-04-26

- [1211326] High CVE-2021-30567: Use after free in DevTools. Reported
by DDV_UA on 2021-05-20

- [1219886] High CVE-2021-30568: Heap buffer overflow in WebGL.
Reported by Yangkang (@dnpushme) of 360 ATA on 2021-06-15

- [1218707] High CVE-2021-30569: Use after free in sqlite. Reported by
Chris Salls (@salls) of Makai Security on 2021-06-11

- [1101897] High CVE-2021-30571: Insufficient policy enforcement in
DevTools. Reported by David Erceg on 2020-07-03

- [1214234] High CVE-2021-30572: Use after free in Autofill. Reported
by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at Qi'anxin
Group on 2021-05-28

- [1216822] High CVE-2021-30573: Use after free in GPU. Reported by
Security For Everyone Team - https://securityforeveryone.com on
2021-06-06

- [1227315] High CVE-2021-30574: Use after free in protocol handling.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2021-07-08

- [1213313] Medium CVE-2021-30575: Out of bounds read in Autofill.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2021-05-26

- [1194896] Medium CVE-2021-30576: Use after free in DevTools.
Reported by David Erceg on 2021-04-01

- [1204811] Medium CVE-2021-30577: Insufficient policy enforcement in
Installer. Reported by Jan van der Put (REQON B.V) on 2021-05-01

- [1201074] Medium CVE-2021-30578: Uninitialized Use in Media.
Reported by Chaoyuan Peng on 2021-04-21

- [1207277] Medium CVE-2021-30579: Use after free in UI framework.
Reported by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at
Qi'anxin Group on 2021-05-10

- [1189092] Medium CVE-2021-30580: Insufficient policy enforcement in
Android intents. Reported by @retsew0x01 on 2021-03-17

- [1194431] Medium CVE-2021-30581: Use after free in DevTools.
Reported by David Erceg on 2021-03-31

- [1205981] Medium CVE-2021-30582: Inappropriate implementation in
Animation. Reported by George Liu on 2021-05-05

- [1179290] Medium CVE-2021-30583: Insufficient policy enforcement in
image handling on Windows. Reported by Muneaki Nishimura (nishimunea)
on 2021-02-17

- [1213350] Medium CVE-2021-30584: Incorrect security UI in Downloads.
Reported by @retsew0x01 on 2021-05-26

- [1023503] Medium CVE-2021-30585: Use after free in sensor handling.
Reported by niarci on 2019-11-11

- [1201032] Medium CVE-2021-30586: Use after free in dialog box
handling on Windows. Reported by kkomdal with kkwon and neodal on
2021-04-21

- [1204347] Medium CVE-2021-30587: Inappropriate implementation in
Compositing on Windows. Reported by Abdulrahman Alqabandi, Microsoft
Browser Vulnerability Research on 2021-04-30

- [1195650] Low CVE-2021-30588: Type Confusion in V8. Reported by Jose
Martinez (tr0y4) from VerSprite Inc. on 2021-04-04

- [1180510] Low CVE-2021-30589: Insufficient validation of untrusted
input in Sharing. Reported by Kirtikumar Anandrao Ramchandani
(@Kirtikumar_A_R) and Patrick Walker (@homesen) on 2021-02-20");
  # https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b961beb2");
  # https://vuxml.freebsd.org/freebsd/76487640-ea29-11eb-a686-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072c2990");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30588");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<92.0.4515.107")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
