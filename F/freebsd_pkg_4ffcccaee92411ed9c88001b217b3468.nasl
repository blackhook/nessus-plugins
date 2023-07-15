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
  script_id(175004);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2022-4376",
    "CVE-2023-0756",
    "CVE-2023-0805",
    "CVE-2023-1178",
    "CVE-2023-1621",
    "CVE-2023-1836",
    "CVE-2023-1965",
    "CVE-2023-2069",
    "CVE-2023-2182"
  );
  script_xref(name:"IAVA", value:"2023-A-0235-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (4ffcccae-e924-11ed-9c88-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 4ffcccae-e924-11ed-9c88-001b217b3468 advisory.

  - An issue has been discovered in GitLab affecting all versions before 15.9.6, all versions starting from
    15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1. Under certain conditions, an
    attacker may be able to map a private email of a GitLab user to their GitLab account on an instance.
    (CVE-2022-4376)

  - An issue has been discovered in GitLab affecting all versions before 15.9.6, all versions starting from
    15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1. The main branch of a repository
    with a specially crafted name allows an attacker to create repositories with malicious code, victims who
    clone or download these repositories will execute arbitrary code on their systems. (CVE-2023-0756)

  - An issue has been discovered in GitLab EE affecting all versions starting from 15.2 before 15.9.6, all
    versions starting from 15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1. A malicious
    group member may continue to have access to the public projects of a public group even after being banned
    from the public group by the owner. (CVE-2023-0805)

  - An issue has been discovered in GitLab CE/EE affecting all versions from 8.6 before 15.9.6, all versions
    starting from 15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1. File integrity may be
    compromised when source code or installation packages are pulled from a tag or from a release containing a
    ref to another commit. (CVE-2023-1178)

  - An issue has been discovered in GitLab EE affecting all versions starting from 12.0 before 15.10.5, all
    versions starting from 15.11 before 15.11.1. A malicious group member may continue to commit to projects
    even from a restricted IP address. (CVE-2023-1621)

  - A cross-site scripting issue has been discovered in GitLab affecting all versions starting from 5.1 before
    15.9.6, all versions starting from 15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1.
    When viewing an XML file in a repository in raw mode, it can be made to render as HTML if viewed on an
    iOS device. (CVE-2023-1836)

  - An issue has been discovered in GitLab EE affecting all versions starting from 14.2 before 15.9.6, all
    versions starting from 15.10 before 15.10.5, all versions starting from 15.11 before 15.11.1. Lack of
    verification on RelayState parameter allowed a maliciously crafted URL to obtain access tokens granted for
    3rd party Group SAML SSO logins. This feature isn't enabled by default. (CVE-2023-1965)

  - An issue has been discovered in GitLab affecting all versions starting from 10.0 before 12.9.8, all
    versions starting from 12.10 before 12.10.7, all versions starting from 13.0 before 13.0.1. A user with
    the role of developer could use the import project feature to leak CI/CD variables. (CVE-2023-2069)

  - An issue has been discovered in GitLab EE affecting all versions starting from 15.10 before 15.10.5, all
    versions starting from 15.11 before 15.11.1. Under certain conditions when OpenID Connect is enabled on an
    instance, it may allow users who are marked as 'external' to become 'regular' users thus leading to
    privilege escalation for those users. (CVE-2023-2182)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/05/02/security-release-gitlab-15-11-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f020e43");
  # https://vuxml.freebsd.org/freebsd/4ffcccae-e924-11ed-9c88-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e63f9687");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2182");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/02");

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
    'gitlab-ce>=15.10.0<15.10.5',
    'gitlab-ce>=15.11.0<15.11.1',
    'gitlab-ce>=9.0<15.9.6'
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
