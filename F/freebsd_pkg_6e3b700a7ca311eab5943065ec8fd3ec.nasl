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

include("compat.inc");

if (description)
{
  script_id(135425);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/16");

  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (6e3b700a-7ca3-11ea-b594-3065ec8fd3ec)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

This updates includes 32 security fixes, including :

- [1019161] High CVE-2020-6454: Use after free in extensions. Reported
by Leecraso and Guang Gong of Alpha Lab, Qihoo 360 on 2019-10-29

- [1043446] High CVE-2020-6423: Use after free in audio. Reported by
Anonymous on 2020-01-18

- [1059669] High CVE-2020-6455: Out of bounds read in WebSQL. Reported
by Nan Wang(@eternalsakura13) and Guang Gong of Alpha Lab, Qihoo 360
on 2020-03-09

- [1031479] Medium CVE-2020-6430: Type Confusion in V8. Reported by
Avihay Cohen @ SeraphicAlgorithms on 2019-12-06

- [1040755] Medium CVE-2020-6456: Insufficient validation of untrusted
input in clipboard. Reported by Michal Bentkowski of Securitum on
2020-01-10

- [852645] Medium CVE-2020-6431: Insufficient policy enforcement in
full screen. Reported by Luan Herrera (@lbherrera_) on 2018-06-14

- [965611] Medium CVE-2020-6432: Insufficient policy enforcement in
navigations. Reported by David Erceg on 2019-05-21

- [1043965] Medium CVE-2020-6433: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-01-21

- [1048555] Medium CVE-2020-6434: Use after free in devtools. Reported
by HyungSeok Han (DaramG) of Theori on 2020-02-04

- [1032158] Medium CVE-2020-6435: Insufficient policy enforcement in
extensions. Reported by Sergei Glazunov of Google Project Zero on
2019-12-09

- [1034519] Medium CVE-2020-6436: Use after free in window management.
Reported by Igor Bukanov from Vivaldi on 2019-12-16

- [639173] Low CVE-2020-6437: Inappropriate implementation in WebView.
Reported by Jann Horn on 2016-08-19

- [714617] Low CVE-2020-6438: Insufficient policy enforcement in
extensions. Reported by Ng Yik Phang on 2017-04-24

- [868145] Low CVE-2020-6439: Insufficient policy enforcement in
navigations. Reported by remkoboonstra on 2018-07-26

- [894477] Low CVE-2020-6440: Inappropriate implementation in
extensions. Reported by David Erceg on 2018-10-11

- [959571] Low CVE-2020-6441: Insufficient policy enforcement in
omnibox. Reported by David Erceg on 2019-05-04

- [1013906] Low CVE-2020-6442: Inappropriate implementation in cache.
Reported by B@rMey on 2019-10-12

- [1040080] Low CVE-2020-6443: Insufficient data validation in
developer tools. Reported by @lovasoa (Ophir LOJKINE) on 2020-01-08

- [922882] Low CVE-2020-6444: Uninitialized Use in WebRTC. Reported by
mlfbrown on 2019-01-17

- [933171] Low CVE-2020-6445: Insufficient policy enforcement in
trusted types. Reported by Jun Kokatsu, Microsoft Browser
Vulnerability Research on 2019-02-18

- [933172] Low CVE-2020-6446: Insufficient policy enforcement in
trusted types. Reported by Jun Kokatsu, Microsoft Browser
Vulnerability Research on 2019-02-18

- [991217] Low CVE-2020-6447: Inappropriate implementation in
developer tools. Reported by David Erceg on 2019-08-06

- [1037872] Low CVE-2020-6448: Use after free in V8. Reported by Guang
Gong of Alpha Lab, Qihoo 360 on 2019-12-26"
  );
  # https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_7.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9efdf3c7"
  );
  # https://vuxml.freebsd.org/freebsd/6e3b700a-7ca3-11ea-b594-3065ec8fd3ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?843ce636"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<81.0.4044.92")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
