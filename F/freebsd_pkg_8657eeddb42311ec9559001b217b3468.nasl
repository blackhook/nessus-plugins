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
  script_id(159496);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2022-0740",
    "CVE-2022-1099",
    "CVE-2022-1100",
    "CVE-2022-1105",
    "CVE-2022-1111",
    "CVE-2022-1120",
    "CVE-2022-1121",
    "CVE-2022-1148",
    "CVE-2022-1157",
    "CVE-2022-1162",
    "CVE-2022-1174",
    "CVE-2022-1175",
    "CVE-2022-1185",
    "CVE-2022-1188",
    "CVE-2022-1189",
    "CVE-2022-1190",
    "CVE-2022-1193"
  );
  script_xref(name:"IAVA", value:"2022-A-0131-S");

  script_name(english:"FreeBSD : Gitlab -- multiple vulnerabilities (8657eedd-b423-11ec-9559-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 8657eedd-b423-11ec-9559-001b217b3468 advisory.

  - Incorrect authorization in the Asana integration's branch restriction feature in all versions of GitLab
    CE/EE starting from version 7.8.0 before 14.7.7, all versions starting from 14.8 before 14.8.5, all
    versions starting from 14.9 before 14.9.2 makes it possible to close Asana tasks from unrestricted
    branches. (CVE-2022-0740)

  - Adding a very large number of tags to a runner in GitLab CE/EE affecting all versions prior to 14.7.7,
    14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allows an attacker to impact the performance of GitLab
    (CVE-2022-1099)

  - A potential DOS vulnerability was discovered in GitLab CE/EE affecting all versions from 13.1 prior to
    14.7.7, 14.8.0 prior to 14.8.5, and 14.9.0 prior to 14.9.2. The api to update an asset as a link from a
    release had a regex check which caused exponential number of backtracks for certain user supplied values
    resulting in high CPU usage. (CVE-2022-1100)

  - An improper access control vulnerability in GitLab CE/EE affecting all versions from 13.11 prior to
    14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allows an unauthorized user to access pipeline
    analytics even when public pipelines are disabled (CVE-2022-1105)

  - A business logic error in Project Import in GitLab CE/EE versions 14.9 prior to 14.9.2, 14.8 prior to
    14.8.5, and 14.0 prior to 14.7.7 under certain conditions caused imported projects to show an incorrect
    user in the 'Access Granted' column in the project membership pages (CVE-2022-1111)

  - Missing filtering in an error message in GitLab CE/EE affecting all versions prior to 14.7.7, 14.8 prior
    to 14.8.5, and 14.9 prior to 14.9.2 exposed sensitive information when an include directive fails in the
    CI/CD configuration. (CVE-2022-1120)

  - A lack of appropriate timeouts in GitLab Pages included in GitLab CE/EE all versions prior to 14.7.7, 14.8
    prior to 14.8.5, and 14.9 prior to 14.9.2 allows an attacker to cause unlimited resource consumption.
    (CVE-2022-1121)

  - Improper authorization in GitLab Pages included with GitLab CE/EE affecting all versions from 11.5 prior
    to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allowed an attacker to steal a user's access
    token on an attacker-controlled private GitLab Pages website and reuse that token on the victim's other
    private websites (CVE-2022-1148)

  - A hardcoded password was set for accounts registered using an OmniAuth provider (e.g. OAuth, LDAP, SAML)
    in GitLab CE/EE versions 14.7 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allowing
    attackers to potentially take over accounts (CVE-2022-1162)

  - A potential DoS vulnerability was discovered in Gitlab CE/EE versions 13.7 before 14.7.7, all versions
    starting from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 allowed an attacker to
    trigger high CPU usage via a special crafted input added in Issues, Merge requests, Milestones, Snippets,
    Wiki pages, etc. (CVE-2022-1174)

  - Improper neutralization of user input in GitLab CE/EE versions 14.4 before 14.7.7, all versions starting
    from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 allowed an attacker to exploit XSS
    by injecting HTML in notes. (CVE-2022-1175)

  - A denial of service vulnerability when rendering RDoc files in GitLab CE/EE versions 10 to 14.7.7, 14.8.0
    to 14.8.5, and 14.9.0 to 14.9.2 allows an attacker to crash the GitLab web application with a maliciously
    crafted RDoc file (CVE-2022-1185)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.1 before 14.7.7, all
    versions starting from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 where a blind
    SSRF attack through the repository mirroring feature was possible. (CVE-2022-1188)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.2 before 14.7.7, all
    versions starting from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 that allowed for
    an unauthorised user to read the the approval rules of a private project. (CVE-2022-1189)

  - Improper handling of user input in GitLab CE/EE versions 8.3 prior to 14.7.7, 14.8 prior to 14.8.5, and
    14.9 prior to 14.9.2 allowed an attacker to exploit a stored XSS by abusing multi-word milestone
    references in issue descriptions, comments, etc. (CVE-2022-1190)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/03/31/critical-security-release-gitlab-14-9-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eea093a9");
  # https://vuxml.freebsd.org/freebsd/8657eedd-b423-11ec-9559-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?944c5d5c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1162");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'gitlab-ce>=0<14.7.7',
    'gitlab-ce>=14.8.0<14.8.5',
    'gitlab-ce>=14.9.0<14.9.2'
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
