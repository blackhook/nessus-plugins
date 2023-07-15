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
  script_id(148704);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-21201",
    "CVE-2021-21202",
    "CVE-2021-21203",
    "CVE-2021-21204",
    "CVE-2021-21205",
    "CVE-2021-21207",
    "CVE-2021-21208",
    "CVE-2021-21209",
    "CVE-2021-21210",
    "CVE-2021-21211",
    "CVE-2021-21212",
    "CVE-2021-21213",
    "CVE-2021-21214",
    "CVE-2021-21215",
    "CVE-2021-21216",
    "CVE-2021-21217",
    "CVE-2021-21218",
    "CVE-2021-21219",
    "CVE-2021-21221"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (f3d86439-9def-11eb-97a0-e09467587c17)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release contains 37 security fixes, including :

- [1025683] High CVE-2021-21201: Use after free in permissions.
Reported by Gengming Liu, Jianyu Chen at Tencent Keen Security Lab on
2019-11-18

- [1188889] High CVE-2021-21202: Use after free in extensions.
Reported by David Erceg on 2021-03-16

- [1192054] High CVE-2021-21203: Use after free in Blink. Reported by
asnine on 2021-03-24

- [1189926] High CVE-2021-21204: Use after free in Blink. Reported by
Chelse Tsai-Simek, Jeanette Ulloa, and Emily Voigtlander of Seesaw on
2021-03-19

- [1165654] High CVE-2021-21205: Insufficient policy enforcement in
navigation. Reported by Alison Huffman, Microsoft Browser
Vulnerability Research on 2021-01-12

- [1195333] High CVE-2021-21221: Insufficient validation of untrusted
input in Mojo. Reported by Guang Gong of Alpha Lab, Qihoo 360 on
2021-04-02

- [1185732] Medium CVE-2021-21207: Use after free in IndexedDB.
Reported by koocola (@alo_cook) and Nan Wang (@eternalsakura13) of 360
Alpha Lab on 2021-03-08

- [1039539] Medium CVE-2021-21208: Insufficient data validation in QR
scanner. Reported by Ahmed Elsobky (@0xsobky) on 2020-01-07

- [1143526] Medium CVE-2021-21209: Inappropriate implementation in
storage. Reported by Tom Van Goethem (@tomvangoethem) on 2020-10-29

- [1184562] Medium CVE-2021-21210: Inappropriate implementation in
Network. Reported by @bananabr on 2021-03-04

- [1103119] Medium CVE-2021-21211: Inappropriate implementation in
Navigation. Reported by Akash Labade (m0ns7er) on 2020-07-08

- [1145024] Medium CVE-2021-21212: Incorrect security UI in Network
Config UI. Reported by Hugo Hue and Sze Yiu Chau of the Chinese
University of Hong Kong on 2020-11-03

- [1161806] Medium CVE-2021-21213: Use after free in WebMIDI. Reported
by raven (@raid_akame) on 2020-12-25

- [1170148] Medium CVE-2021-21214: Use after free in Network API.
Reported by Anonymous on 2021-01-24

- [1172533] Medium CVE-2021-21215: Inappropriate implementation in
Autofill. Reported by Abdulrahman Alqabandi, Microsoft Browser
Vulnerability Research on 2021-01-30

- [1173297] Medium CVE-2021-21216: Inappropriate implementation in
Autofill. Reported by Abdulrahman Alqabandi, Microsoft Browser
Vulnerability Research on 2021-02-02

- [1166462] Low CVE-2021-21217: Uninitialized Use in PDFium. Reported
by Zhou Aiting (@zhouat1) of Qihoo 360 Vulcan Team on 2021-01-14

- [1166478] Low CVE-2021-21218: Uninitialized Use in PDFium. Reported
by Zhou Aiting (@zhouat1) of Qihoo 360 Vulcan Team on 2021-01-14

- [1166972] Low CVE-2021-21219: Uninitialized Use in PDFium. Reported
by Zhou Aiting (@zhouat1) of Qihoo 360 Vulcan Team on 2021-01-15");
  # https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec023c8b");
  # https://vuxml.freebsd.org/freebsd/f3d86439-9def-11eb-97a0-e09467587c17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2e18135");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21214");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<90.0.4430.72")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
