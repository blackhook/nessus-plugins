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
  script_id(154316);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-37981",
    "CVE-2021-37982",
    "CVE-2021-37983",
    "CVE-2021-37984",
    "CVE-2021-37985",
    "CVE-2021-37986",
    "CVE-2021-37987",
    "CVE-2021-37988",
    "CVE-2021-37989",
    "CVE-2021-37990",
    "CVE-2021-37991",
    "CVE-2021-37992",
    "CVE-2021-37993",
    "CVE-2021-37994",
    "CVE-2021-37995",
    "CVE-2021-37996"
  );
  script_xref(name:"IAVA", value:"2021-A-0491-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (bdaecfad-3117-11ec-b3b0-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release contains 19 security fixes, including :

- [1246631] High CVE-2021-37981: Heap buffer overflow in Skia.
Reported by Yangkang (@dnpushme) of 360 ATA on 2021-09-04

- [1248661] High CVE-2021-37982: Use after free in Incognito. Reported
by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at Qi'anxin
Group on 2021-09-11

- [1249810] High CVE-2021-37983: Use after free in Dev Tools. Reported
by Zhihua Yao of KunLun Lab on 2021-09-15

- [1253399] High CVE-2021-37984: Heap buffer overflow in PDFium.
Reported by Antti Levomaki, Joonas Pihlaja andChristian Jali from
Forcepoint on 2021-09-27

- [1241860] High CVE-2021-37985: Use after free in V8. Reported by
Yangkang (@dnpushme) of 360 ATA on 2021-08-20

- [1242404] Medium CVE-2021-37986: Heap buffer overflow in Settings.
Reported by raven (@raid_akame) on 2021-08-23

- [1206928] Medium CVE-2021-37987: Use after free in Network APIs.
Reported by Yangkang (@dnpushme) of 360 ATA on 2021-05-08

- [1228248] Medium CVE-2021-37988: Use after free in Profiles.
Reported by raven (@raid_akame) on 2021-07-12

- [1233067] Medium CVE-2021-37989: Inappropriate implementation in
Blink. Reported by Matt Dyas, Ankur Sundara on 2021-07-26

- [1247395] Medium CVE-2021-37990: Inappropriate implementation in
WebView. Reported by Kareem Selim of CyShield on 2021-09-07

- [1250660] Medium CVE-2021-37991: Race in V8. Reported by Samuel
Gross of Google Project Zero on 2021-09-17

- [1253746] Medium CVE-2021-37992: Out of bounds read in WebAudio.
Reported by sunburst@Ant Security Light-Year Lab on 2021-09-28

- [1255332] Medium CVE-2021-37993: Use after free in PDF
Accessibility. Reported by Cassidy Kim of Amber Security Lab, OPPO
Mobile Telecommunications Corp. Ltd. on 2021-10-02

- [1243020] Medium CVE-2021-37996: Insufficient validation of
untrusted input in Downloads. Reported by Anonymous on 2021-08-24

- [1100761] Low CVE-2021-37994: Inappropriate implementation in iFrame
Sandbox. Reported by David Erceg on 2020-06-30

- [1242315] Low CVE-2021-37995: Inappropriate implementation in WebApp
Installer. Reported by Terence Eden on 2021-08-23");
  # https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0836418");
  # https://vuxml.freebsd.org/freebsd/bdaecfad-3117-11ec-b3b0-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae669e5c");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37993");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<95.0.4638.54")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
