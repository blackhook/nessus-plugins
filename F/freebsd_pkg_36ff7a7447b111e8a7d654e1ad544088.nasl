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

include("compat.inc");

if (description)
{
  script_id(109330);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-6084", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6115", "CVE-2018-6116", "CVE-2018-6117");

  script_name(english:"FreeBSD : chromium -- vulnerability (36ff7a74-47b1-11e8-a7d6-54e1ad544088)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

62 security fixes in this release :

- [826626] Critical CVE-2018-6085: Use after free in Disk Cache.
Reported by Ned Williamson on 2018-03-28

- [827492] Critical CVE-2018-6086: Use after free in Disk Cache.
Reported by Ned Williamson on 2018-03-30

- [813876] High CVE-2018-6087: Use after free in WebAssembly. Reported
by Anonymous on 2018-02-20

- [822091] High CVE-2018-6088: Use after free in PDFium. Reported by
Anonymous on 2018-03-15

- [808838] High CVE-2018-6089: Same origin policy bypass in Service
Worker. Reported by Rob Wu on 2018-02-04

- [820913] High CVE-2018-6090: Heap buffer overflow in Skia. Reported
by ZhanJia Song on 2018-03-12

- [771933] High CVE-2018-6091: Incorrect handling of plug-ins by
Service Worker. Reported by Jun Kokatsu (@shhnjk) on 2017-10-05

- [819869] High CVE-2018-6092: Integer overflow in WebAssembly.
Reported by Natalie Silvanovich of Google Project Zero on 2018-03-08

- [780435] Medium CVE-2018-6093: Same origin bypass in Service Worker.
Reported by Jun Kokatsu (@shhnjk) on 2017-11-01

- [633030] Medium CVE-2018-6094: Exploit hardening regression in
Oilpan. Reported by Chris Rohlf on 2016-08-01

- [637098] Medium CVE-2018-6095: Lack of meaningful user interaction
requirement before file upload. Reported by Abdulrahman Alqabandi
(@qab) on 2016-08-11

- [776418] Medium CVE-2018-6096: Fullscreen UI spoof. Reported by
WenXu Wu of Tencent's Xuanwu Lab on 2017-10-19

- [806162] Medium CVE-2018-6097: Fullscreen UI spoof. Reported by
xisigr of Tencent's Xuanwu Lab on 2018-01-26

- [798892] Medium CVE-2018-6098: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-01-03

- [808825] Medium CVE-2018-6099: CORS bypass in ServiceWorker.
Reported by Jun Kokatsu (@shhnjk) on 2018-02-03

- [811117] Medium CVE-2018-6100: URL spoof in Omnibox. Reported by
Lnyas Zhang on 2018-02-11

- [813540] Medium CVE-2018-6101: Insufficient protection of remote
debugging prototol in DevTools . Reported by Rob Wu on 2018-02-19

- [813814] Medium CVE-2018-6102: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-02-20

- [816033] Medium CVE-2018-6103: UI spoof in Permissions. Reported by
Khalil Zhani on 2018-02-24

- [820068] Medium CVE-2018-6104: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-03-08

- [803571] Medium CVE-2018-6105: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-01-18

- [805729] Medium CVE-2018-6106: Incorrect handling of promises in V8.
Reported by lokihardt of Google Project Zero on 2018-01-25

- [808316] Medium CVE-2018-6107: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-02-02

- [816769] Medium CVE-2018-6108: URL spoof in Omnibox. Reported by
Khalil Zhani on 2018-02-27

- [710190] Low CVE-2018-6109: Incorrect handling of files by FileAPI.
Reported by Dominik Weber (@DoWeb_) on 2017-04-10

- [777737] Low CVE-2018-6110: Incorrect handling of plaintext files
via file:// . Reported by Wenxiang Qian (aka blastxiang) on 2017-10-24

- [780694] Low CVE-2018-6111: Heap-use-after-free in DevTools.
Reported by Khalil Zhani on 2017-11-02

- [798096] Low CVE-2018-6112: Incorrect URL handling in DevTools.
Reported by Rob Wu on 2017-12-29

- [805900] Low CVE-2018-6113: URL spoof in Navigation. Reported by
Khalil Zhani on 2018-01-25

- [811691] Low CVE-2018-6114: CSP bypass. Reported by Lnyas Zhang on
2018-02-13

- [819809] Low CVE-2018-6115: SmartScreen bypass in downloads.
Reported by James Feher on 2018-03-07

- [822266] Low CVE-2018-6116: Incorrect low memory handling in
WebAssembly. Reported by Jin from Chengdu Security Response Center of
Qihoo 360 Technology Co. Ltd. on 2018-03-15

- [822465] Low CVE-2018-6117: Confusing autofill settings. Reported by
Spencer Dailey on 2018-03-15

- [822424] Low CVE-2018-6084: Incorrect use of Distributed Objects in
Google Software Updater on MacOS. Reported by Ian Beer of Google
Project Zero on 2018-03-15"
  );
  # https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db76b488"
  );
  # https://vuxml.freebsd.org/freebsd/36ff7a74-47b1-11e8-a7d6-54e1ad544088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?288bbd0c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<66.0.3359.117")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
