#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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
  script_id(156027);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-4052",
    "CVE-2021-4053",
    "CVE-2021-4054",
    "CVE-2021-4055",
    "CVE-2021-4056",
    "CVE-2021-4057",
    "CVE-2021-4058",
    "CVE-2021-4059",
    "CVE-2021-4061",
    "CVE-2021-4062",
    "CVE-2021-4063",
    "CVE-2021-4064",
    "CVE-2021-4065",
    "CVE-2021-4066",
    "CVE-2021-4067",
    "CVE-2021-4068",
    "CVE-2021-4078",
    "CVE-2021-4079"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (18ac074c-579f-11ec-aac7-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 18ac074c-579f-11ec-aac7-3065ec8fd3ec advisory.

  - Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4067)

  - Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (CVE-2021-4052)

  - Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4053)

  - Incorrect security UI in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (CVE-2021-4054)

  - Heap buffer overflow in extensions in Google Chrome prior to 96.0.4664.93 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-4055)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cd0fa03");
  # https://vuxml.freebsd.org/freebsd/18ac074c-579f-11ec-aac7-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9b505b2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4079");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'chromium<96.0.4664.93'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
