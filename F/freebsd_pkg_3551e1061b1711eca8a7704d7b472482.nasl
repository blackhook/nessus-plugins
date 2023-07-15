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
include("compat.inc");

if (description)
{
  script_id(153826);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/14");

  script_cve_id("CVE-2021-37956", "CVE-2021-37957", "CVE-2021-37958", "CVE-2021-37959", "CVE-2021-37960", "CVE-2021-37961", "CVE-2021-37962", "CVE-2021-37963", "CVE-2021-37964", "CVE-2021-37965", "CVE-2021-37966", "CVE-2021-37967", "CVE-2021-37968", "CVE-2021-37969", "CVE-2021-37970", "CVE-2021-37971", "CVE-2021-37972");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (3551e106-1b17-11ec-a8a7-704d7b472482)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This update contains 19 security fixes, including :

- [1243117] High CVE-2021-37956: Use after free in Offline use.
Reported by Huyna at Viettel Cyber Security on 2021-08-24

- [1242269] High CVE-2021-37957: Use after free in WebGPU. Reported by
Looben Yang on 2021-08-23

- [1223290] High CVE-2021-37958: Inappropriate implementation in
Navigation. Reported by James Lee (@Windowsrcer) on 2021-06-24

- [1229625] High CVE-2021-37959: Use after free in Task Manager.
Reported by raven (@raid_akame) on 2021-07-15

- [1247196] High CVE-2021-37960: Inappropriate implementation in Blink
graphics. Reported by Atte Kettunen of OUSPG on 2021-09-07

- [1228557] Medium CVE-2021-37961: Use after free in Tab Strip.
Reported by Khalil Zhani on 2021-07-13

- [1231933] Medium CVE-2021-37962: Use after free in Performance
Manager. Reported by Sri on 2021-07-22

- [1199865] Medium CVE-2021-37963: Side-channel information leakage in
DevTools. Reported by Daniel Genkin and Ayush Agarwal, University of
Michigan, Eyal Ronen and Shaked Yehezkel, Tel Aviv University, Sioli
O'Connell, University of Adelaide, and Jason Kim, Georgia Institute of
Technology on 2021-04-16

- [1203612] Medium CVE-2021-37964: Inappropriate implementation in
ChromeOS Networking. Reported by Hugo Hue and Sze Yiu Chau of the
Chinese University of Hong Kong on 2021-04-28

- [1239709] Medium CVE-2021-37965: Inappropriate implementation in
Background Fetch API. Reported by Maurice Dauer on 2021-08-13

- [1238944] Medium CVE-2021-37966: Inappropriate implementation in
Compositing. Reported by Mohit Raj (shadow2639) on 2021-08-11

- [1243622] Medium CVE-2021-37967: Inappropriate implementation in
Background Fetch API. Reported by SorryMybad (@S0rryMybad) of Kunlun
Lab on 2021-08-26

- [1245053] Medium CVE-2021-37968: Inappropriate implementation in
Background Fetch API. Reported by Maurice Dauer on 2021-08-30

- [1245879] Medium CVE-2021-37969: Inappropriate implementation in
Google Updater. Reported by Abdelhamid Naceri (halov) on 2021-09-02

- [1248030] Medium CVE-2021-37970: Use after free in File System API.
Reported by SorryMybad (@S0rryMybad) of Kunlun Lab on 2021-09-09

- [1219354] Low CVE-2021-37971: Incorrect security UI in Web Browser
UI. Reported by Rayyan Bijoora on 2021-06-13

- [1234259] Low CVE-2021-37972: Out of bounds read in libjpeg-turbo.
Reported by Xu Hanyu and Lu Yutao from Panguite-Forensics-Lab of
Qianxin on 2021-07-29"
  );
  # https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop_21.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9293f232"
  );
  # https://vuxml.freebsd.org/freebsd/3551e106-1b17-11ec-a8a7-704d7b472482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f54a11b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37957");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<94.0.4606.54")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
