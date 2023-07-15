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
  script_id(153062);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2021-30606", "CVE-2021-30607", "CVE-2021-30608", "CVE-2021-30609", "CVE-2021-30610", "CVE-2021-30611", "CVE-2021-30612", "CVE-2021-30613", "CVE-2021-30614", "CVE-2021-30615", "CVE-2021-30616", "CVE-2021-30617", "CVE-2021-30618", "CVE-2021-30619", "CVE-2021-30620", "CVE-2021-30621", "CVE-2021-30622", "CVE-2021-30623", "CVE-2021-30624");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a7732806-0b2a-11ec-836b-3065ec8fd3ec)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This release contains 27 security fixes, including :

- [1233975] High CVE-2021-30606: Use after free in Blink. Reported by
Nan Wang (@eternalsakura13) and koocola (@alo_cook) of 360 Alpha Lab
on 2021-07-28

- [1235949] High CVE-2021-30607: Use after free in Permissions.
Reported by Weipeng Jiang (@Krace) from Codesafe Team of Legendsec at
Qi'anxin Group on 2021-08-03

- [1219870] High CVE-2021-30608: Use after free in Web Share. Reported
by Huyna at Viettel Cyber Security on 2021-06-15

- [1239595] High CVE-2021-30609: Use after free in Sign-In. Reported
by raven (@raid_akame) on 2021-08-13

- [1200440] High CVE-2021-30610: Use after free in Extensions API.
Reported by Igor Bukanov from Vivaldi on 2021-04-19

- [1233942] Medium CVE-2021-30611: Use after free in WebRTC. Reported
by Nan Wang (@eternalsakura13) and koocola (@alo_cook) of 360 Alpha
Lab on 2021-07-28

- [1234284] Medium CVE-2021-30612: Use after free in WebRTC. Reported
by Nan Wang (@eternalsakura13) and koocola (@alo_cook) of 360 Alpha
Lab on 2021-07-29

- [1209622] Medium CVE-2021-30613: Use after free in Base internals.
Reported by Yangkang (@dnpushme) of 360 ATA on 2021-05-16

- [1207315] Medium CVE-2021-30614: Heap buffer overflow in TabStrip.
Reported by Huinian Yang (@vmth6) of Amber Security Lab, OPPO Mobile
Telecommunications Corp. Ltd. on 2021-05-10

- [1208614] Medium CVE-2021-30615: Cross-origin data leak in
Navigation. Reported by NDevTK on 2021-05-12

- [1231432] Medium CVE-2021-30616: Use after free in Media. Reported
by Anonymous on 2021-07-21

- [1226909] Medium CVE-2021-30617: Policy bypass in Blink. Reported by
NDevTK on 2021-07-07

- [1232279] Medium CVE-2021-30618: Inappropriate implementation in
DevTools. Reported by @DanAmodio and @mattaustin from Contrast
Security on 2021-07-23

- [1235222] Medium CVE-2021-30619: UI Spoofing in Autofill. Reported
by Alesandro Ortiz on 2021-08-02

- [1063518] Medium CVE-2021-30620: Insufficient policy enforcement in
Blink. Reported by Jun Kokatsu, Microsoft Browser Vulnerability
Research on 2020-03-20

- [1204722] Medium CVE-2021-30621: UI Spoofing in Autofill. Reported
by Abdulrahman Alqabandi, Microsoft Browser Vulnerability Research on
2021-04-30

- [1224419] Medium CVE-2021-30622: Use after free in WebApp Installs.
Reported by Jun Kokatsu, Microsoft Browser Vulnerability Research on
2021-06-28

- [1223667] Low CVE-2021-30623: Use after free in Bookmarks. Reported
by Leecraso and Guang Gong of 360 Alpha Lab on 2021-06-25

- [1230513] Low CVE-2021-30624: Use after free in Autofill. Reported
by Wei Yuan of MoyunSec VLab on 2021-07-19"
  );
  # https://chromereleases.googleblog.com/2021/08/stable-channel-update-for-desktop_31.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc7074cc"
  );
  # https://vuxml.freebsd.org/freebsd/a7732806-0b2a-11ec-836b-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf35cc60"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30623");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/07");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<93.0.4577.63")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
