#%NASL_MIN_LEVEL 70300
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160295);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1477",
    "CVE-2022-1478",
    "CVE-2022-1479",
    "CVE-2022-1481",
    "CVE-2022-1482",
    "CVE-2022-1483",
    "CVE-2022-1484",
    "CVE-2022-1485",
    "CVE-2022-1486",
    "CVE-2022-1487",
    "CVE-2022-1488",
    "CVE-2022-1489",
    "CVE-2022-1490",
    "CVE-2022-1491",
    "CVE-2022-1492",
    "CVE-2022-1493",
    "CVE-2022-1494",
    "CVE-2022-1495",
    "CVE-2022-1496",
    "CVE-2022-1497",
    "CVE-2022-1498",
    "CVE-2022-1499",
    "CVE-2022-1500",
    "CVE-2022-1501"
  );
  script_xref(name:"IAVA", value:"2022-A-0183-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (26f2123b-c6c6-11ec-b66f-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 26f2123b-c6c6-11ec-b66f-3065ec8fd3ec advisory.

  - Use after free in File Manager in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1496)

  - Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1477)

  - Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1478)

  - Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1479)

  - Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1481)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e31ed7e1");
  # https://vuxml.freebsd.org/freebsd/26f2123b-c6c6-11ec-b66f-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce5a3c3c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1496");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

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
    'chromium<101.0.4951.41'
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
