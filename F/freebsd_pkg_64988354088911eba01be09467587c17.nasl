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
  script_id(141284);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id("CVE-2020-15967", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15970", "CVE-2020-15971", "CVE-2020-15972", "CVE-2020-15973", "CVE-2020-15974", "CVE-2020-15975", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15980", "CVE-2020-15981", "CVE-2020-15982", "CVE-2020-15983", "CVE-2020-15984", "CVE-2020-15985", "CVE-2020-15986", "CVE-2020-15987", "CVE-2020-15988", "CVE-2020-15989", "CVE-2020-15990", "CVE-2020-15991", "CVE-2020-15992", "CVE-2020-6557");
  script_xref(name:"IAVA", value:"2020-A-0443-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (64988354-0889-11eb-a01b-e09467587c17)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome releases reports :

This release contains 35 security fixes, including :

- [1127322] Critical CVE-2020-15967: Use after free in payments.
Reported by Man Yue Mo of GitHub Security Lab on 2020-09-11

- [1126424] High CVE-2020-15968: Use after free in Blink. Reported by
Anonymous on 2020-09-09

- [1124659] High CVE-2020-15969: Use after free in WebRTC. Reported by
Anonymous on 2020-09-03

- [1108299] High CVE-2020-15970: Use after free in NFC. Reported by
Man Yue Mo of GitHub Security Lab on 2020-07-22

- [1114062] High CVE-2020-15971: Use after free in printing. Reported
by Jun Kokatsu, Microsoft Browser Vulnerability Research on 2020-08-07

- [1115901] High CVE-2020-15972: Use after free in audio. Reported by
Anonymous on 2020-08-13

- [1133671] High CVE-2020-15990: Use after free in autofill. Reported
by Rong Jian and Guang Gong of Alpha Lab, Qihoo 360 on 2020-09-30

- [1133688] High CVE-2020-15991: Use after free in password manager.
Reported by Rong Jian and Guang Gong of Alpha Lab, Qihoo 360 on
2020-09-30

- [1106890] Medium CVE-2020-15973: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-07-17

- [1104103] Medium CVE-2020-15974: Integer overflow in Blink. Reported
by Juno Im (junorouse) of Theori on 2020-07-10

- [1110800] Medium CVE-2020-15975: Integer overflow in SwiftShader.
Reported by Anonymous on 2020-07-29

- [1123522] Medium CVE-2020-15976: Use after free in WebXR. Reported
by YoungJoo Lee (@ashuu_lee) of Raon Whitehat on 2020-08-31

- [1083278] Medium CVE-2020-6557: Inappropriate implementation in
networking. Reported by Matthias Gierlings and Marcus Brinkmann (NDS
Ruhr-University Bochum) on 2020-05-15

- [1097724] Medium CVE-2020-15977: Insufficient data validation in
dialogs. Reported by Narendra Bhati (@imnarendrabhati) on 2020-06-22

- [1116280] Medium CVE-2020-15978: Insufficient data validation in
navigation. Reported by Luan Herrera (@lbherrera_) on 2020-08-14

- [1127319] Medium CVE-2020-15979: Inappropriate implementation in V8.
Reported by Avihay Cohen (@SeraphicAlgorithms) on 2020-09-11

- [1092453] Medium CVE-2020-15980: Insufficient policy enforcement in
Intents. Reported by Yongke Wang (@Rudykewang) and Aryb1n (@aryb1n) of
Tencent Security Xuanwu Lab on 2020-06-08

- [1123023] Medium CVE-2020-15981: Out of bounds read in audio.
Reported by Christoph Guttandin on 2020-08-28

- [1039882] Medium CVE-2020-15982: Side-channel information leakage in
cache. Reported by Luan Herrera (@lbherrera_) on 2020-01-07

- [1076786] Medium CVE-2020-15983: Insufficient data validation in
webUI. Reported by Jun Kokatsu, Microsoft Browser Vulnerability
Research on 2020-04-30

- [1080395] Medium CVE-2020-15984: Insufficient policy enforcement in
Omnibox. Reported by Rayyan Bijoora on 2020-05-07

- [1099276] Medium CVE-2020-15985: Inappropriate implementation in
Blink. Reported by Abdulrahman Alqabandi, Microsoft Browser
Vulnerability Research on 2020-06-25

- [1100247] Medium CVE-2020-15986: Integer overflow in media. Reported
by Mark Brand of Google Project Zero on 2020-06-29

- [1127774] Medium CVE-2020-15987: Use after free in WebRTC. Reported
by Philipp Hancke on 2020-09-14

- [1110195] Medium CVE-2020-15992: Insufficient policy enforcement in
networking. Reported by Alison Huffman, Microsoft Browser
Vulnerability Research on 2020-07-28

- [1092518] Low CVE-2020-15988: Insufficient policy enforcement in
downloads. Reported by Samuel Attard on 2020-06-08

- [1108351] Low CVE-2020-15989: Uninitialized Use in PDFium. Reported
by Gareth Evans (Microsoft) on 2020-07-22"
  );
  # https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac3b0244"
  );
  # https://vuxml.freebsd.org/freebsd/64988354-0889-11eb-a01b-e09467587c17.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12510b9f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15992");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<86.0.4240.75")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
