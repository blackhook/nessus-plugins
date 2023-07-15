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
  script_id(162511);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-34170",
    "CVE-2022-34171",
    "CVE-2022-34172",
    "CVE-2022-34173",
    "CVE-2022-34174",
    "CVE-2022-34175"
  );

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (25be46f0-f25d-11ec-b62a-00e081b7aa2d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 25be46f0-f25d-11ec-b62a-00e081b7aa2d advisory.

  - In Jenkins 2.320 through 2.355 (both inclusive) and LTS 2.332.1 through LTS 2.332.3 (both inclusive) the
    help icon does not escape the feature name that is part of its tooltip, effectively undoing the fix for
    SECURITY-1955, resulting in a cross-site scripting (XSS) vulnerability exploitable by attackers with
    Job/Configure permission. (CVE-2022-34170)

  - In Jenkins 2.321 through 2.355 (both inclusive) and LTS 2.332.1 through LTS 2.332.3 (both inclusive) the
    HTML output generated for new symbol-based SVG icons includes the 'title' attribute of 'l:ionicon' (until
    Jenkins 2.334) and 'alt' attribute of 'l:icon' (since Jenkins 2.335) without further escaping, resulting
    in a cross-site scripting (XSS) vulnerability. (CVE-2022-34171)

  - In Jenkins 2.340 through 2.355 (both inclusive) symbol-based icons unescape previously escaped values of
    'tooltip' parameters, resulting in a cross-site scripting (XSS) vulnerability. (CVE-2022-34172)

  - In Jenkins 2.340 through 2.355 (both inclusive) the tooltip of the build button in list views supports
    HTML without escaping the job display name, resulting in a cross-site scripting (XSS) vulnerability
    exploitable by attackers with Job/Configure permission. (CVE-2022-34173)

  - In Jenkins 2.355 and earlier, LTS 2.332.3 and earlier, an observable timing discrepancy on the login form
    allows distinguishing between login attempts with an invalid username, and login attempts with a valid
    username and wrong password, when using the Jenkins user database security realm. (CVE-2022-34174)

  - Jenkins 2.335 through 2.355 (both inclusive) allows attackers in some cases to bypass a protection
    mechanism, thereby directly accessing some view fragments containing sensitive information, bypassing any
    permission checks in the corresponding view. (CVE-2022-34175)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2022-06-22/");
  # https://vuxml.freebsd.org/freebsd/25be46f0-f25d-11ec-b62a-00e081b7aa2d.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79178b57");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34175");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
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
    'jenkins-lts<2.346.1',
    'jenkins<2.356'
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
