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
  script_id(107044);
  script_version("3.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2017-15420", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (8e986b2b-1baa-11e8-a944-54ee754af08e)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

Several security fixes in this release, including :

- [780450] High CVE-2018-6031: Use after free in PDFium. Reported by
Anonymous on 2017-11-01

- [787103] High CVE-2018-6032: Same origin bypass in Shared Worker.
Reported by Jun Kokatsu (@shhnjk) on 2017-11-20

- [793620] High CVE-2018-6033: Race when opening downloaded files.
Reported by Juho Nurminen on 2017-12-09

- [784183] Medium CVE-2018-6034: Integer overflow in Blink. Reported
by Tobias Klein (www.trapkit.de) on 2017-11-12

- [797500] Medium CVE-2018-6035: Insufficient isolation of devtools
from extensions. Reported by Rob Wu on 2017-12-23

- [797500] Medium CVE-2018-6035: Insufficient isolation of devtools
from extensions. Reported by Rob Wu on 2017-12-23

- [753645] Medium CVE-2018-6037: Insufficient user gesture
requirements in autofill. Reported by Paul Stone of Context
Information Security on 2017-08-09

- [774174] Medium CVE-2018-6038: Heap buffer overflow in WebGL.
Reported by cloudfuzzer on 2017-10-12

- [775527] Medium CVE-2018-6039: XSS in DevTools. Reported by Juho
Nurminen on 2017-10-17

- [778658] Medium CVE-2018-6040: Content security policy bypass.
Reported by WenXu Wu of Tencent's Xuanwu Lab on 2017-10-26

- [760342] Medium CVE-2018-6041: URL spoof in Navigation. Reported by
Luan Herrera on 2017-08-29

- [773930] Medium CVE-2018-6042: URL spoof in OmniBox. Reported by
Khalil Zhani on 2017-10-12

- [785809] Medium CVE-2018-6043: Insufficient escaping with external
URL handlers. Reported by 0x09AL on 2017-11-16

- [797497] Medium CVE-2018-6045: Insufficient isolation of devtools
from extensions. Reported by Rob Wu on 2017-12-23

- [798163] Medium CVE-2018-6046: Insufficient isolation of devtools
from extensions. Reported by Rob Wu on 2017-12-31

- [799847] Medium CVE-2018-6047: Cross origin URL leak in WebGL.
Reported by Masato Kinugawa on 2018-01-08

- [763194] Low CVE-2018-6048: Referrer policy bypass in Blink.
Reported by Jun Kokatsu (@shhnjk) on 2017-09-08

- [771848] Low CVE-2017-15420: URL spoofing in Omnibox. Reported by
Drew Springall (@_aaspring_) on 2017-10-05

- [774438] Low CVE-2018-6049: UI spoof in Permissions. Reported by
WenXu Wu of Tencent's Xuanwu Lab on 2017-10-13

- [774842] Low CVE-2018-6050: URL spoof in OmniBox. Reported by
Jonathan Kew on 2017-10-15

- [441275] Low CVE-2018-6051: Referrer leak in XSS Auditor. Reported
by Antonio Sanso (@asanso) on 2014-12-11

- [615608] Low CVE-2018-6052: Incomplete no-referrer policy
implementation. Reported by Tanner Emek on 2016-05-28

- [758169] Low CVE-2018-6053: Leak of page thumbnails in New Tab Page.
Reported by Asset Kabdenov on 2017-08-23

- [797511] Low CVE-2018-6054: Use after free in WebUI. Reported by Rob
Wu on 2017-12-24"
  );
  # https://chromereleases.googleblog.com/2018/01/stable-channel-update-for-desktop_24.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26e44d0b"
  );
  # https://vuxml.freebsd.org/freebsd/8e986b2b-1baa-11e8-a944-54ee754af08e.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efc939e5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<64.0.3282.119")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
