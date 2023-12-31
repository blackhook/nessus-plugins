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
  script_id(70701);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5598", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (81f866ad-41a4-11e3-a4af-0025905a4771)");
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

MFSA 2013-93 Miscellaneous memory safety hazards (rv:25.0 / rv:24.1 /
rv:17.0.10)

MFSA 2013-94 Spoofing addressbar though SELECT element

MFSA 2013-95 Access violation with XSLT and uninitialized data

MFSA 2013-96 Improperly initialized memory and overflows in some
JavaScript functions

MFSA 2013-97 Writing to cycle collected object during image decoding

MFSA 2013-98 Use-after-free when updating offline cache

MFSA 2013-99 Security bypass of PDF.js checks using iframes

MFSA 2013-100 Miscellaneous use-after-free issues found through ASAN
fuzzing

MFSA 2013-101 Memory corruption in workers

MFSA 2013-102 Use-after-free in HTML document templates"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-93.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-93/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-94.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-94/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-95.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-95/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-96.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-96/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-97.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-97/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-98.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-98/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-99.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-99/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-100.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-100/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-101.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-101/"
  );
  # https://www.mozilla.org/security/announce/2013/mfsa2013-102.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-102/"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/"
  );
  # https://vuxml.freebsd.org/freebsd/81f866ad-41a4-11e3-a4af-0025905a4771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?184ef1f9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<24.1.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<25.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<24.1.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.22")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<24.1.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
