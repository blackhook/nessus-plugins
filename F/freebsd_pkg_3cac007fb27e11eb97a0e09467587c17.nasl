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
  script_id(149425);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (3cac007f-b27e-11eb-97a0-e09467587c17)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Chrome Releases reports :

This release contains 19 security fixes, including :

- [1180126] High CVE-2021-30506: Incorrect security UI in Web App
Installs. Reported by @retsew0x01 on 2021-02-19

- [1178202] High CVE-2021-30507: Inappropriate implementation in
Offline. Reported by Alison Huffman, Microsoft Browser Vulnerability
Research on 2021-02-14

- [1195340] High CVE-2021-30508: Heap buffer overflow in Media Feeds.
Reported by Leecraso and Guang Gong of 360 Alpha Lab on 2021-04-02

- [1196309] High CVE-2021-30509: Out of bounds write in Tab Strip.
Reported by David Erceg on 2021-04-06

- [1197436] High CVE-2021-30510: Race in Aura. Reported by Weipeng
Jiang (@Krace) from Codesafe Team of Legendsec at Qi'anxin Group on
2021-04-09

- [1197875] High CVE-2021-30511: Out of bounds read in Tab Groups.
Reported by David Erceg on 2021-04-10

- [1200019] High CVE-2021-30512: Use after free in Notifications.
Reported by ZhanJia Song on 2021-04-17

- [1200490] High CVE-2021-30513: Type Confusion in V8. Reported by Man
Yue Mo of GitHub Security Lab on 2021-04-19

- [1200766] High CVE-2021-30514: Use after free in Autofill. Reported
by koocola (@alo_cook) and Nan Wang (@eternalsakura13) of 360 Alpha
Lab on 2021-04-20

- [1201073] High CVE-2021-30515: Use after free in File API. Reported
by Rong Jian and Guang Gong of 360 Alpha Lab on 2021-04-21

- [1201446] High CVE-2021-30516: Heap buffer overflow in History.
Reported by ZhanJia Song on 2021-04-22

- [1203122] High CVE-2021-30517: Type Confusion in V8. Reported by
laural on 2021-04-27

- [1203590] High CVE-2021-30518: Heap buffer overflow in Reader Mode.
Reported by Jun Kokatsu, Microsoft Browser Vulnerability Research on
2021-04-28

- [1194058] Medium CVE-2021-30519: Use after free in Payments.
Reported by asnine on 2021-03-30

- [1193362] Medium CVE-2021-30520: Use after free in Tab Strip.
Reported by Khalil Zhani on 2021-04-03"
  );
  # https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e7dcca1"
  );
  # https://vuxml.freebsd.org/freebsd/3cac007f-b27e-11eb-97a0-e09467587c17.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24c1bb62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30520");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");
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

if (pkg_test(save_report:TRUE, pkg:"chromium<90.0.4430.212")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
