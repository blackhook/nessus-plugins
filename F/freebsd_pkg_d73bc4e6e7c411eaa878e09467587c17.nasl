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
  script_id(139886);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/30");

  script_cve_id("CVE-2020-6558", "CVE-2020-6559", "CVE-2020-6560", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6563", "CVE-2020-6564", "CVE-2020-6565", "CVE-2020-6566", "CVE-2020-6567", "CVE-2020-6568", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (d73bc4e6-e7c4-11ea-a878-e09467587c17)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This update includes 20 security fixes, including :

- [1109120] High CVE-2020-6558: Insufficient policy enforcement in
iOS. Reported by Alison Huffman, Microsoft Browser Vulnerability
Research on 2020-07-24

- [1116706] High CVE-2020-6559: Use after free in presentation API.
Reported by Liu Wei and Wu Zekai of Tencent Security Xuanwu Lab on
2020-08-15

- [1108181] Medium CVE-2020-6560: Insufficient policy enforcement in
autofill. Reported by Nadja Ungethuem from www.unnex.de on 2020-07-22

- [932892] Medium CVE-2020-6561: Inappropriate implementation in
Content Security Policy. Reported by Rob Wu on 2019-02-16

- [1086845] Medium CVE-2020-6562: Insufficient policy enforcement in
Blink. Reported by Masato Kinugawa on 2020-05-27

- [1104628] Medium CVE-2020-6563: Insufficient policy enforcement in
intent handling. Reported by Pedro Oliveira on 2020-07-12

- [841622] Medium CVE-2020-6564: Incorrect security UI in permissions.
Reported by Khalil Zhani on 2018-05-10

- [1029907] Medium CVE-2020-6565: Incorrect security UI in Omnibox.
Reported by Khalil Zhani on 2019-12-02

- [1065264] Medium CVE-2020-6566: Insufficient policy enforcement in
media. Reported by Jun Kokatsu, Microsoft Browser Vulnerability
Research on 2020-03-27

- [937179] Low CVE-2020-6567: Insufficient validation of untrusted
input in command line handling. Reported by Joshua Graham of TSS on
2019-03-01

- [1092451] Low CVE-2020-6568: Insufficient policy enforcement in
intent handling. Reported by Yongke Wang(@Rudykewang) and
Aryb1n(@aryb1n) of Tencent Security Xuanwu Lab on 2020-06-08

- [995732] Low CVE-2020-6569: Integer overflow in WebUSB. Reported by
guaixiaomei on 2019-08-20

- [1084699] Low CVE-2020-6570: Side-channel information leakage in
WebRTC. Reported by Signal/Tenable on 2020-05-19

- [1085315] Low CVE-2020-6571: Incorrect security UI in Omnibox.
Reported by Rayyan Bijoora on 2020-05-21"
  );
  # https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop_25.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e44927e"
  );
  # https://vuxml.freebsd.org/freebsd/d73bc4e6-e7c4-11ea-a878-e09467587c17.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d3dc658"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6559");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/27");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<85.0.4183.83")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
