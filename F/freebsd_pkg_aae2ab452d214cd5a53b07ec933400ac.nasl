#%NASL_MIN_LEVEL 80900
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
  script_id(177384);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-2930",
    "CVE-2023-2931",
    "CVE-2023-2932",
    "CVE-2023-2933",
    "CVE-2023-2934",
    "CVE-2023-2935",
    "CVE-2023-2936",
    "CVE-2023-3079"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/28");

  script_name(english:"FreeBSD : electron24 -- multiple vulnerabilities (aae2ab45-2d21-4cd5-a53b-07ec933400ac)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the aae2ab45-2d21-4cd5-a53b-07ec933400ac advisory.

  - Use after free in Extensions in Google Chrome prior to 114.0.5735.90 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2930)

  - Use after free in PDF in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: High) (CVE-2023-2931,
    CVE-2023-2932, CVE-2023-2933)

  - Out of bounds memory access in Mojo in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-2934)

  - Type Confusion in V8 in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2935,
    CVE-2023-2936)

  - Type confusion in V8 in Google Chrome prior to 114.0.5735.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3079)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-44xq-533g-gj79");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-5ccq-3h49-vjp2");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-7g49-wq8x-r6rh");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-8mwf-hvfp-6xfg");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-mqff-qm67-cr66");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-qrc7-3p69-2jpf");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-w3xh-m877-x3c2");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-x723-3x32-qg44");
  # https://vuxml.freebsd.org/freebsd/aae2ab45-2d21-4cd5-a53b-07ec933400ac.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57edee70");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2933");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-3079");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:electron24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'electron24<24.5.1'
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
