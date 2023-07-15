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
  script_id(168310);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4176",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195"
  );
  script_xref(name:"IAVA", value:"2022-A-0501-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (5f7ed6ea-70a7-11ed-92ce-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 5f7ed6ea-70a7-11ed-92ce-3065ec8fd3ec advisory.

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4174)

  - Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4175)

  - Out of bounds write in Lacros Graphics in Google Chrome on Chrome OS and Lacros prior to 108.0.5359.71
    allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially
    exploit heap corruption via UI interactions. (Chromium security severity: High) (CVE-2022-4176)

  - Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a
    user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI
    interaction. (Chromium security severity: High) (CVE-2022-4177)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2022-4178)

  - Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4179)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4180)

  - Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4184)

  - Inappropriate implementation in Navigation in Google Chrome on iOS prior to 108.0.5359.71 allowed a remote
    attacker to spoof the contents of the modal dialogue via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an
    attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 108.0.5359.71 allowed a
    remote attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4187)

  - Insufficient validation of untrusted input in CORS in Google Chrome on Android prior to 108.0.5359.71
    allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2022-4188)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 108.0.5359.71 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2022-4189)

  - Insufficient data validation in Directory in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4190)

  - Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced
    a user to engage in specific UI interaction to potentially exploit heap corruption via profile
    destruction. (Chromium security severity: Medium) (CVE-2022-4191)

  - Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Medium) (CVE-2022-4192)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 108.0.5359.71 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4193)

  - Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass Safe Browsing warnings via a malicious file. (Chromium security severity: Medium)
    (CVE-2022-4195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf710783");
  # https://vuxml.freebsd.org/freebsd/5f7ed6ea-70a7-11ed-92ce-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87ed9a77");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4194");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ungoogled-chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'chromium<108.0.5359.71',
    'ungoogled-chromium<108.0.5359.71'
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
