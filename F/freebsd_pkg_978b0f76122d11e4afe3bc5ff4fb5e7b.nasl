#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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
include('compat.inc');

if (description)
{
  script_id(76720);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1551", "CVE-2014-1552", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1561");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (978b0f76-122d-11e4-afe3-bc5ff4fb5e7b)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Project reports :

MFSA 2014-66 IFRAME sandbox same-origin access through redirect

MFSA 2014-65 Certificate parsing broken by non-standard character
encoding

MFSA 2014-64 Crash in Skia library when scaling high quality images

MFSA 2014-63 Use-after-free while when manipulating certificates in
the trusted cache

MFSA 2014-62 Exploitable WebGL crash with Cesium JavaScript library

MFSA 2014-61 Use-after-free with FireOnStateChange event

MFSA 2014-60 Toolbar dialog customization event spoofing

MFSA 2014-59 Use-after-free in DirectWrite font handling

MFSA 2014-58 Use-after-free in Web Audio due to incorrect control
message ordering

MFSA 2014-57 Buffer overflow during Web Audio buffering for playback

MFSA 2014-56 Miscellaneous memory safety hazards (rv:31.0 / rv:24.7)"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-56.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-56/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-57.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-57/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-58.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-58/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-59.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-59/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-60.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-60/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-61.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-61/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-62.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-62/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-63.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-63/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-64.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-64/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-65.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-65/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-66.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-66/"
  );
  # https://www.mozilla.org/security/announce/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/"
  );
  # https://vuxml.freebsd.org/freebsd/978b0f76-122d-11e4-afe3-bc5ff4fb5e7b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30b8d994"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<31.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<24.7.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<31.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<24.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<24.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"nss<3.16.1_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
