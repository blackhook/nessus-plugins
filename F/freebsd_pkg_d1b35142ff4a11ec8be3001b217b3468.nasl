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
  script_id(162969);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id(
    "CVE-2022-1954",
    "CVE-2022-1963",
    "CVE-2022-1981",
    "CVE-2022-1983",
    "CVE-2022-1999",
    "CVE-2022-2185",
    "CVE-2022-2227",
    "CVE-2022-2228",
    "CVE-2022-2229",
    "CVE-2022-2230",
    "CVE-2022-2235",
    "CVE-2022-2243",
    "CVE-2022-2244",
    "CVE-2022-2250",
    "CVE-2022-2270",
    "CVE-2022-2281"
  );

  script_name(english:"FreeBSD : Gitlab -- multiple vulnerabilities (d1b35142-ff4a-11ec-8be3-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the d1b35142-ff4a-11ec-8be3-001b217b3468 advisory.

  - A Regular Expression Denial of Service vulnerability in GitLab CE/EE affecting all versions from 1.0.2
    prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker to make a GitLab
    instance inaccessible via specially crafted web server response headers (CVE-2022-1954)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.4 before 14.10.5, all
    versions starting from 15.0 before 15.0.4, all versions starting from 15.1 before 15.1.1. GitLab reveals
    if a user has enabled two-factor authentication on their account in the HTML source, to unauthenticated
    users. (CVE-2022-1963)

  - An issue has been discovered in GitLab EE affecting all versions starting from 12.2 prior to 14.10.5, 15.0
    prior to 15.0.4, and 15.1 prior to 15.1.1. In GitLab, if a group enables the setting to restrict access to
    users belonging to specific domains, that allow-list may be bypassed if a Maintainer uses the 'Invite a
    group' feature to invite a group that has members that don't comply with domain allow-list.
    (CVE-2022-1981)

  - Incorrect authorization in GitLab EE affecting all versions from 10.7 prior to 14.10.5, 15.0 prior to
    15.0.4, and 15.1 prior to 15.1.1, allowed an attacker already in possession of a valid Deploy Key or a
    Deploy Token to misuse it from any location to access Container Registries even when IP address
    restrictions were configured. (CVE-2022-1983)

  - An issue has been discovered in GitLab CE/EE affecting all versions from 8.13 prior to 14.10.5, 15.0 prior
    to 15.0.4, and 15.1 prior to 15.1.1. Under certain conditions, using the REST API an unprivileged user was
    able to change labels description. (CVE-2022-1999)

  - A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5,
    15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where it was possible for an unauthorised user to execute
    arbitrary code on the server using the project import feature. (CVE-2022-2185)

  - Improper access control in the runner jobs API in GitLab CE/EE affecting all versions prior to 14.10.5,
    15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows a previous maintainer of a project with a specific
    runner to access job and project meta data under certain conditions (CVE-2022-2227)

  - Information exposure in GitLab EE affecting all versions from 12.0 prior to 14.10.5, 15.0 prior to 15.0.4,
    and 15.1 prior to 15.1.1 allows an attacker with the appropriate access tokens to obtain CI variables in a
    group with using IP-based access restrictions even if the GitLab Runner is calling from outside the
    allowed IP range (CVE-2022-2228)

  - An improper authorization issue in GitLab CE/EE affecting all versions from 13.7 prior to 14.10.5, 15.0
    prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker to extract the value of an unprotected
    variable they know the name of in public projects or private projects they're a member of. (CVE-2022-2229)

  - A Stored Cross-Site Scripting vulnerability in the project settings page in GitLab CE/EE affecting all
    versions from 14.4 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allows an attacker to
    execute arbitrary JavaScript code in GitLab on a victim's behalf. (CVE-2022-2230)

  - Insufficient sanitization in GitLab EE's external issue tracker affecting all versions from 14.5 prior to
    14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker to perform cross-site scripting
    when a victim clicks on a maliciously crafted ZenTao link (CVE-2022-2235)

  - An access control vulnerability in GitLab EE/CE affecting all versions from 14.8 prior to 14.10.5, 15.0
    prior to 15.0.4, and 15.1 prior to 15.1.1, allows authenticated users to enumerate issues in non-linked
    sentry projects. (CVE-2022-2243)

  - An improper authorization vulnerability in GitLab EE/CE affecting all versions from 14.8 prior to 14.10.5,
    15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allows project memebers with reporter role to manage
    issues in project's error tracking feature. (CVE-2022-2244)

  - An open redirect vulnerability in GitLab EE/CE affecting all versions from 11.1 prior to 14.10.5, 15.0
    prior to 15.0.4, and 15.1 prior to 15.1.1, allows an attacker to redirect users to an arbitrary location
    if they trust the URL. (CVE-2022-2250)

  - An issue has been discovered in GitLab affecting all versions starting from 12.4 before 14.10.5, all
    versions starting from 15.0 before 15.0.4, all versions starting from 15.1 before 15.1.1. GitLab was
    leaking Conan packages names due to incorrect permissions verification. (CVE-2022-2270)

  - An information disclosure vulnerability in GitLab EE affecting all versions from 12.5 prior to 14.10.5,
    15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allows disclosure of release titles if group milestones
    are associated with any project releases. (CVE-2022-2281)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/06/30/critical-security-release-gitlab-15-1-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20e24be1");
  # https://vuxml.freebsd.org/freebsd/d1b35142-ff4a-11ec-8be3-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ec7ab49");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
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
    'gitlab-ce>=0<14.10.5',
    'gitlab-ce>=15.0.0<15.0.4',
    'gitlab-ce>=15.1.0<15.1.1'
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
