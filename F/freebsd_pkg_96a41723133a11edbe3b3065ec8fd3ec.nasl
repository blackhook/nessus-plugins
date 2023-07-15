#
# (C) Tenable, Inc.
#
# @NOAGENT@
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

include('compat.inc');

if (description)
{
  script_id(163766);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-2603",
    "CVE-2022-2604",
    "CVE-2022-2605",
    "CVE-2022-2606",
    "CVE-2022-2607",
    "CVE-2022-2608",
    "CVE-2022-2609",
    "CVE-2022-2610",
    "CVE-2022-2611",
    "CVE-2022-2612",
    "CVE-2022-2613",
    "CVE-2022-2614",
    "CVE-2022-2615",
    "CVE-2022-2616",
    "CVE-2022-2617",
    "CVE-2022-2618",
    "CVE-2022-2619",
    "CVE-2022-2620",
    "CVE-2022-2621",
    "CVE-2022-2622",
    "CVE-2022-2623",
    "CVE-2022-2624"
  );
  script_xref(name:"IAVA", value:"2022-A-0304-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (96a41723-133a-11ed-be3b-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 96a41723-133a-11ed-be3b-3065ec8fd3ec advisory.

  - Use after free in Omnibox. (CVE-2022-2603)

  - Use after free in Safe Browsing. (CVE-2022-2604)

  - Out of bounds read in Dawn. (CVE-2022-2605)

  - Use after free in Managed devices API. (CVE-2022-2606)

  - Use after free in Tab Strip. (CVE-2022-2607)

  - Use after free in Overview Mode. (CVE-2022-2608)

  - Use after free in Nearby Share. (CVE-2022-2609)

  - Insufficient policy enforcement in Background Fetch. (CVE-2022-2610)

  - Inappropriate implementation in Fullscreen API. (CVE-2022-2611)

  - Side-channel information leakage in Keyboard input. (CVE-2022-2612)

  - Use after free in Input. (CVE-2022-2613)

  - Use after free in Sign-In Flow. (CVE-2022-2614)

  - Insufficient policy enforcement in Cookies. (CVE-2022-2615)

  - Inappropriate implementation in Extensions API. (CVE-2022-2616)

  - Use after free in Extensions API. (CVE-2022-2617)

  - Insufficient validation of untrusted input in Internals. (CVE-2022-2618)

  - Insufficient validation of untrusted input in Settings. (CVE-2022-2619)

  - Use after free in WebUI. (CVE-2022-2620)

  - Use after free in Extensions. (CVE-2022-2621)

  - Insufficient validation of untrusted input in Safe Browsing. (CVE-2022-2622)

  - Use after free in Offline. (CVE-2022-2623)

  - Heap buffer overflow in PDF. (CVE-2022-2624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?806fe022");
  # https://vuxml.freebsd.org/freebsd/96a41723-133a-11ed-be3b-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac3a3e8e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'chromium<104.0.5112.79'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
