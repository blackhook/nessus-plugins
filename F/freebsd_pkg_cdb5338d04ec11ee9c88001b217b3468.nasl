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
  script_id(176831);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-0121",
    "CVE-2023-0508",
    "CVE-2023-0921",
    "CVE-2023-1204",
    "CVE-2023-1825",
    "CVE-2023-2001",
    "CVE-2023-2013",
    "CVE-2023-2015",
    "CVE-2023-2132",
    "CVE-2023-2198",
    "CVE-2023-2199",
    "CVE-2023-2442",
    "CVE-2023-2485",
    "CVE-2023-2589"
  );
  script_xref(name:"IAVA", value:"2023-A-0275-S");

  script_name(english:"FreeBSD : Gitlab -- Vulnerability (cdb5338d-04ec-11ee-9c88-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the cdb5338d-04ec-11ee-9c88-001b217b3468 advisory.

  - A lack of length validation in GitLab CE/EE affecting all versions from 8.3 before 15.10.8, 15.11 before
    15.11.7, and 16.0 before 16.0.2 allows an authenticated attacker to create a large Issue description via
    GraphQL which, when repeatedly requested, saturates CPU usage. (CVE-2023-0921)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.1 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A user could
    use an unverified email as a public email and commit email by sending a specifically crafted request on
    user update settings. (CVE-2023-1204)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.4 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A
    DollarMathPostFilter Regular Expression Denial of Service in was possible by sending crafted payloads to
    the preview_markdown endpoint. (CVE-2023-2132)

  - A denial of service issue was discovered in GitLab CE/EE affecting all versions starting from 13.2.4
    before 15.10.8, all versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before
    16.0.2 which allows an attacker to cause high resource consumption using malicious test report artifacts.
    (CVE-2023-0121)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.4 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. Open
    redirection was possible via HTTP response splitting in the NPM package API. (CVE-2023-0508)

  - An issue has been discovered in GitLab EE affecting all versions starting from 15.7 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. It was
    possible to disclose issue notes to an unauthorized user at project export. (CVE-2023-1825)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 15.10.8, all versions starting
    from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. An attacker was able to spoof
    protected tags, which could potentially lead a victim to download malicious code. (CVE-2023-2001)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 1.2 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. An issue was
    found that allows someone to abuse a discrepancy between the Web application display and the git command
    line interface to social engineer victims into cloning non-trusted code. (CVE-2023-2013)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.8 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A reflected
    XSS was possible when creating new abuse reports which allows attackers to perform arbitrary actions on
    behalf of victims. (CVE-2023-2015)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 8.7 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A Regular
    Expression Denial of Service was possible via sending crafted payloads to the preview_markdown endpoint.
    (CVE-2023-2198)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.0 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A Regular
    Expression Denial of Service was possible via sending crafted payloads to the preview_markdown endpoint.
    (CVE-2023-2199)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.11 before 15.11.7,
    all versions starting from 16.0 before 16.0.2. A specially crafted merge request could lead to a stored
    XSS on the client side which allows attackers to perform arbitrary actions on behalf of victims.
    (CVE-2023-2442)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.1 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. A malicious
    maintainer in a project can escalate other users to Owners in that project if they import members from
    another project that those other users are Owners of. (CVE-2023-2485)

  - An issue has been discovered in GitLab EE affecting all versions starting from 12.0 before 15.10.8, all
    versions starting from 15.11 before 15.11.7, all versions starting from 16.0 before 16.0.2. An attacker
    can clone a repository from a public project, from a disallowed IP, even after the top-level group has
    enabled IP restrictions on the group. (CVE-2023-2589)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/06/05/security-release-gitlab-16-0-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59d6d04");
  # https://vuxml.freebsd.org/freebsd/cdb5338d-04ec-11ee-9c88-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db06486e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2015");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
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
    'gitlab-ce>=1.2<15.9.8',
    'gitlab-ce>=15.10.0<15.10.8',
    'gitlab-ce>=15.11.0<15.11.7',
    'gitlab-ce>=16.0.0<16.0.2'
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
