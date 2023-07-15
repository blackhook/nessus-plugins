#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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
  script_id(120969);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_cve_id("CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335", "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339", "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343", "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347", "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351", "CVE-2018-18352", "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355", "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (546d4dd4-10ea-11e9-b407-080027ef1a23)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Google Chrome Releases reports :

43 security fixes in this release, including :

- High CVE-2018-17480: Out of bounds write in V8

- High CVE-2018-17481: Use after free in PDFium

- High CVE-2018-18335: Heap buffer overflow in Skia

- High CVE-2018-18336: Use after free in PDFium

- High CVE-2018-18337: Use after free in Blink

- High CVE-2018-18338: Heap buffer overflow in Canvas

- High CVE-2018-18339: Use after free in WebAudio

- High CVE-2018-18340: Use after free in MediaRecorder

- High CVE-2018-18341: Heap buffer overflow in Blink

- High CVE-2018-18342: Out of bounds write in V8

- High CVE-2018-18343: Use after free in Skia

- High CVE-2018-18344: Inappropriate implementation in Extensions

- High To be allocated: Multiple issues in SQLite via WebSQL

- Medium CVE-2018-18345: Inappropriate implementation in Site
Isolation

- Medium CVE-2018-18346: Incorrect security UI in Blink

- Medium CVE-2018-18347: Inappropriate implementation in Navigation

- Medium CVE-2018-18348: Inappropriate implementation in Omnibox

- Medium CVE-2018-18349: Insufficient policy enforcement in Blink

- Medium CVE-2018-18350: Insufficient policy enforcement in Blink

- Medium CVE-2018-18351: Insufficient policy enforcement in Navigation

- Medium CVE-2018-18352: Inappropriate implementation in Media

- Medium CVE-2018-18353: Inappropriate implementation in Network
Authentication

- Medium CVE-2018-18354: Insufficient data validation in Shell
Integration

- Medium CVE-2018-18355: Insufficient policy enforcement in URL
Formatter

- Medium CVE-2018-18356: Use after free in Skia

- Medium CVE-2018-18357: Insufficient policy enforcement in URL
Formatter

- Medium CVE-2018-18358: Insufficient policy enforcement in Proxy

- Medium CVE-2018-18359: Out of bounds read in V8

- Low To be allocated: Inappropriate implementation in PDFium

- Low To be allocated: Use after free in Extensions

- Low To be allocated: Inappropriate implementation in Navigation

- Low To be allocated: Inappropriate implementation in Navigation

- Low To be allocated: Insufficient policy enforcement in Navigation

- Low To be allocated: Insufficient policy enforcement in URL
Formatter

- Medium To be allocated: Insufficient policy enforcement in Payments

- Various fixes from internal audits, fuzzing and other initiatives"
  );
  # https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?084b0392"
  );
  # https://vuxml.freebsd.org/freebsd/546d4dd4-10ea-11e9-b407-080027ef1a23.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdc6abb9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18359");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<71.0.3578.80")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
