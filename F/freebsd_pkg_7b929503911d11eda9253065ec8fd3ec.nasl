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
  script_id(169806);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2023-0128",
    "CVE-2023-0129",
    "CVE-2023-0130",
    "CVE-2023-0131",
    "CVE-2023-0132",
    "CVE-2023-0133",
    "CVE-2023-0134",
    "CVE-2023-0135",
    "CVE-2023-0136",
    "CVE-2023-0137",
    "CVE-2023-0138",
    "CVE-2023-0139",
    "CVE-2023-0140",
    "CVE-2023-0141"
  );
  script_xref(name:"IAVA", value:"2023-A-0029-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (7b929503-911d-11ed-a925-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 7b929503-911d-11ed-a925-3065ec8fd3ec advisory.

  - Use after free in Overview Mode in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0128)

  - Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page and specific interactions. (Chromium security severity: High) (CVE-2023-0129)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-0130)

  - Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote
    attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-0131)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0132)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0133)

  - Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via database corruption and a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-0134, CVE-2023-0135)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0136)

  - Heap buffer overflow in Platform Apps in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed an
    attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via
    a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-0137)

  - Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-0138)

  - Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0139)

  - Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0140)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-0141)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/01/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc413e40");
  # https://vuxml.freebsd.org/freebsd/7b929503-911d-11ed-a925-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92fb34cc");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ungoogled-chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'chromium<109.0.5414.74',
    'ungoogled-chromium<109.0.5414.74'
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
