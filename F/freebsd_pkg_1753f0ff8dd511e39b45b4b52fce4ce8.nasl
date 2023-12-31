#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72312);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479", "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483", "CVE-2014-1484", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (1753f0ff-8dd5-11e3-9b45-b4b52fce4ce8)");
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

MFSA 2014-01 Miscellaneous memory safety hazards (rv:27.0 / rv:24.3)

MFSA 2014-02 Clone protected content with XBL scopes

MFSA 2014-03 UI selection timeout missing on download prompts

MFSA 2014-04 Incorrect use of discarded images by RasterImage

MFSA 2014-05 Information disclosure with *FromPoint on iframes

MFSA 2014-06 Profile path leaks to Android system log

MFSA 2014-07 XSLT stylesheets treated as styles in Content Security
Policy

MFSA 2014-08 Use-after-free with imgRequestProxy and image proccessing

MFSA 2014-09 Cross-origin information leak through web workers

MFSA 2014-10 Firefox default start page UI content invokable by script

MFSA 2014-11 Crash when using web workers with asm.js

MFSA 2014-12 NSS ticket handling issues

MFSA 2014-13 Inconsistent JavaScript handling of access to Window
objects"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-01.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-01/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-02.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-02/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-03.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-03/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-04.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-04/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-05.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-05/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-06.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-06/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-07.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-07/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-08.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-08/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-09.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-09/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-10.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-10/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-11.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-11/"
  );
  # https://www.mozilla.org/security/announce/2014/mfsa2014-12.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-12/"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/"
  );
  # https://vuxml.freebsd.org/freebsd/1753f0ff-8dd5-11e3-9b45-b4b52fce4ce8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b25afc14"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (pkg_test(save_report:TRUE, pkg:"firefox>25.0,1<27.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox<24.3.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<27.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<24.3.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.24")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<24.3.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
