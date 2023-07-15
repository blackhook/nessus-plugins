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
  script_id(107243);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/09");

  script_cve_id("CVE-2017-11215", "CVE-2017-11225", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072", "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"FreeBSD : chromium -- vulnerability (555af074-22b9-11e8-9799-54ee754af08e)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Google Chrome Releases reports :

45 security fixes in this release :

- [758848] High CVE-2017-11215: Use after free in Flash. Reported by
JieZeng of Tencent Zhanlu Lab on 2017-08-25

- [758863] High CVE-2017-11225: Use after free in Flash. Reported by
JieZeng of Tencent Zhanlu Lab on 2017-08-25

- [780919] High CVE-2018-6060: Use after free in Blink. Reported by
Omair on 2017-11-02

- [794091] High CVE-2018-6061: Race condition in V8. Reported by Guang
Gong of Alpha Team, Qihoo 360 on 2017-12-12

- [780104] High CVE-2018-6062: Heap buffer overflow in Skia. Reported
by Anonymous on 2017-10-31

- [789959] High CVE-2018-6057: Incorrect permissions on shared memory.
Reported by Gal Beniamini of Google Project Zero on 2017-11-30

- [792900] High CVE-2018-6063: Incorrect permissions on shared memory.
Reported by Gal Beniamini of Google Project Zero on 2017-12-07

- [798644] High CVE-2018-6064: Type confusion in V8. Reported by
lokihardt of Google Project Zero on 2018-01-03

- [808192] High CVE-2018-6065: Integer overflow in V8. Reported by
Mark Brand of Google Project Zero on 2018-02-01

- [799477] Medium CVE-2018-6066: Same Origin Bypass via canvas.
Reported by Masato Kinugawa on 2018-01-05

- [779428] Medium CVE-2018-6067: Buffer overflow in Skia. Reported by
Ned Williamson on 2017-10-30

- [779428] Medium CVE-2018-6067: Buffer overflow in Skia. Reported by
Ned Williamson on 2017-10-30

- [799918] Medium CVE-2018-6069: Stack buffer overflow in Skia.
Reported by Wanglu and Yangkang(@dnpushme) of Qihoo360 Qex Team on
2018-01-08

- [668645] Medium CVE-2018-6070: CSP bypass through extensions.
Reported by Rob Wu on 2016-11-25

- [777318] Medium CVE-2018-6071: Heap bufffer overflow in Skia.
Reported by Anonymous on 2017-10-23

- [791048] Medium CVE-2018-6072: Integer overflow in PDFium. Reported
by Atte Kettunen of OUSPG on 2017-12-01

- [804118] Medium CVE-2018-6073: Heap bufffer overflow in WebGL.
Reported by Omair on 2018-01-20

- [809759] Medium CVE-2018-6074: Mark-of-the-Web bypass. Reported by
Abdulrahman Alqabandi (@qab) on 2018-02-06

- [608669] Medium CVE-2018-6075: Overly permissive cross origin
downloads. Reported by Inti De Ceukelaire (intigriti.com) on
2016-05-03

- [758523] Medium CVE-2018-6076: Incorrect handling of URL fragment
identifiers in Blink. Reported by Mateusz Krzeszowiec on 2017-08-24

- [778506] Medium CVE-2018-6077: Timing attack using SVG filters.
Reported by Khalil Zhani on 2017-10-26

- [793628] Medium CVE-2018-6078: URL Spoof in OmniBox. Reported by
Khalil Zhani on 2017-12-10

- [788448] Medium CVE-2018-6079: Information disclosure via texture
data in WebGL. Reported by Ivars Atteka on 2017-11-24

- [792028] Medium CVE-2018-6080: Information disclosure in IPC call.
Reported by Gal Beniamini of Google Project Zero on 2017-12-05

- [797525] Low CVE-2018-6081: XSS in interstitials. Reported by Rob Wu
on 2017-12-24

- [767354] Low CVE-2018-6082: Circumvention of port blocking. Reported
by WenXu Wu of Tencent's Xuanwu Lab on 2017-09-21

- [771709] Low CVE-2018-6083: Incorrect processing of AppManifests.
Reported by Jun Kokatsu (@shhnjk) on 2017-10-04"
  );
  # https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68129919"
  );
  # https://vuxml.freebsd.org/freebsd/555af074-22b9-11e8-9799-54ee754af08e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d451c55d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11225");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<65.0.3325.146")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
