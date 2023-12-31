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
  script_id(65847);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0790", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0797", "CVE-2013-0798", "CVE-2013-0799", "CVE-2013-0800");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (94976433-9c74-11e2-a9fc-d43d7e0c7c02)");
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

MFSA 2013-30 Miscellaneous memory safety hazards (rv:20.0 / rv:17.0.5)

MFSA 2013-31 Out-of-bounds write in Cairo library

MFSA 2013-32 Privilege escalation through Mozilla Maintenance Service

MFSA 2013-33 World read and write access to app_tmp directory on
Android

MFSA 2013-34 Privilege escalation through Mozilla Updater

MFSA 2013-35 WebGL crash with Mesa graphics driver on Linux

MFSA 2013-36 Bypass of SOW protections allows cloning of protected
nodes

MFSA 2013-37 Bypass of tab-modal dialog origin disclosure

MFSA 2013-38 Cross-site scripting (XSS) using timed history
navigations

MFSA 2013-39 Memory corruption while rendering grayscale PNG images

MFSA 2013-40 Out-of-bounds array read in CERT_DecodeCertPackage"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-30.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-30/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-31.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-31/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-32.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-32/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-33.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-33/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-34.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-34/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-35.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-35/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-36.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-36/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-37.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-37/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-38.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-38/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-39.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-39/"
  );
  # http://www.mozilla.org/security/announce/2013/mfsa2013-40.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-40/"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/"
  );
  # https://vuxml.freebsd.org/freebsd/94976433-9c74-11e2-a9fc-d43d7e0c7c02.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?131425f2"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/08");
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

if (pkg_test(save_report:TRUE, pkg:"firefox>18.0,1<20.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox<17.0.5,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<17.0.5,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<17.0.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.17")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird>11.0<17.0.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
