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
  script_id(110700);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-12358", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12368", "CVE-2018-12369", "CVE-2018-12370", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5186", "CVE-2018-5187", "CVE-2018-5188");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (cd81806c-26e7-4d4a-8425-02724a2f48af)");
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
"Mozilla Foundation reports :

CVE-2018-12359: Buffer overflow using computed size of canvas element

CVE-2018-12360: Use-after-free when using focus()

CVE-2018-12361: Integer overflow in SwizzleData

CVE-2018-12358: Same-origin bypass using service worker and
redirection

CVE-2018-12362: Integer overflow in SSSE3 scaler

CVE-2018-5156: Media recorder segmentation fault when track type is
changed during capture

CVE-2018-12363: Use-after-free when appending DOM nodes

CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

CVE-2018-12365: Compromised IPC child process can list local filenames

CVE-2018-12371: Integer overflow in Skia library during edge builder
allocation

CVE-2018-12366: Invalid data handling during QCMS transformations

CVE-2018-12367: Timing attack mitigation of
PerformanceNavigationTiming

CVE-2018-12368: No warning when opening executable SettingContent-ms
files

CVE-2018-12369: WebExtension security permission checks bypassed by
embedded experiments

CVE-2018-12370: SameSite cookie protections bypassed when exiting
Reader View

CVE-2018-5186: Memory safety bugs fixed in Firefox 61

CVE-2018-5187: Memory safety bugs fixed in Firefox 60 and Firefox ESR
60.1

CVE-2018-5188: Memory safety bugs fixed in Firefox 60, Firefox ESR
60.1, and Firefox ESR 52.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-15/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-16/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-17/"
  );
  # https://vuxml.freebsd.org/freebsd/cd81806c-26e7-4d4a-8425-02724a2f48af.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74cb5870"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:waterfox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<61.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.2.1.19_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.49.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.49.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr>=60.0,1<60.1.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<52.9.0_1,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<52.9.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<52.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<52.9.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<52.9.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
