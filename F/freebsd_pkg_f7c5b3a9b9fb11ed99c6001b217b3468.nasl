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
  script_id(172086);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/06");

  script_cve_id(
    "CVE-2022-3381",
    "CVE-2022-3758",
    "CVE-2022-4007",
    "CVE-2022-4289",
    "CVE-2022-4331",
    "CVE-2022-4462",
    "CVE-2023-0050",
    "CVE-2023-0223",
    "CVE-2023-0483",
    "CVE-2023-1072",
    "CVE-2023-1084"
  );
  script_xref(name:"IAVA", value:"2023-A-0122-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (f7c5b3a9-b9fb-11ed-99c6-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the f7c5b3a9-b9fb-11ed-99c6-001b217b3468 advisory.

  - An issue has been discovered in GitLab affecting all versions starting from 10.0 to 15.7.8, 15.8 prior to
    15.8.4 and 15.9 prior to 15.9.2. A crafted URL could be used to redirect users to arbitrary sites. This is
    a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N, 4.3). It is now mitigated in the
    latest release and is assigned CVE-2022-3381. (CVE-2022-3381)

  - An issue has been discovered in GitLab affecting all versions starting from 15.5 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. Due to improper
    permissions checks an unauthorised user was able to read, add or edit a users private snippet. This is a
    medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N, 5.4). It is now mitigated in the
    latest release and is assigned CVE-2022-3758. (CVE-2022-3758)

  - A issue has been discovered in GitLab CE/EE affecting all versions from 15.3 prior to 15.7.8, version 15.8
    prior to 15.8.4, and version 15.9 prior to 15.9.2  A cross-site scripting vulnerability was found in the
    title field of work items that allowed attackers to perform arbitrary actions on behalf of victims at
    client side. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N, 5.4). It is
    now mitigated in the latest release and is assigned CVE-2022-4007. (CVE-2022-4007)

  - An issue has been discovered in GitLab affecting all versions starting from 15.3 before 15.7.8, versions
    of 15.8 before 15.8.4, and version 15.9 before 15.9.2. Google IAP details in Prometheus integration were
    not hidden, could be leaked from instance, group, or project settings to other users. This is a medium
    severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N, 6.4). It is now mitigated in the latest
    release and is assigned CVE-2022-4289. (CVE-2022-4289)

  - An issue has been discovered in GitLab EE affecting all versions starting from 15.1 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. If a group with
    SAML SSO enabled is transferred to a new namespace as a child group, it's possible previously removed
    malicious maintainer or owner of the child group can still gain access to the group via SSO or a SCIM
    token to perform actions on the group. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N, 5.7). It is now mitigated in the latest release and is
    assigned CVE-2022-4331. (CVE-2022-4331)

  - An issue has been discovered in GitLab affecting all versions starting from 12.8 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. This
    vulnerability could allow a user to unmask the Discord Webhook URL through viewing the raw API response.
    This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N, 5.0). It is now mitigated
    in the latest release and is assigned CVE-2022-4462. (CVE-2022-4462)

  - An issue has been discovered in GitLab affecting all versions starting from 13.7 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. A specially
    crafted Kroki diagram could lead to a stored XSS on the client side which allows attackers to perform
    arbitrary actions on behalf of victims. This is a high severity issue
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N, 8.7). It is now mitigated in the latest release and is
    assigned CVE-2023-0050. (CVE-2023-0050)

  - An issue has been discovered in GitLab affecting all versions starting from 15.5 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. Non-project
    members could retrieve release descriptions via the API, even if the release visibility is restricted to
    project members only in the project settings. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 5.3). It is now mitigated in the latest release and is
    assigned CVE-2023-0223. (CVE-2023-0223)

  - An issue has been discovered in GitLab affecting all versions starting from 12.1 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. It was possible
    for a project maintainer to extract a Datadog integration API key by modifying the site. This is a medium
    severity issue (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N, 5.5). It is now mitigated in the latest
    release and is assigned CVE-2023-0483. (CVE-2023-0483)

  - An issue has been discovered in GitLab affecting all versions starting from 9.0 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. It was possible
    to trigger a resource depletion attack due to improper filtering for number of requests to read commits
    details. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L, 4.3). It is now
    mitigated in the latest release and is assigned CVE-2023-1072. (CVE-2023-1072)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 15.7.8, all versions starting
    from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. A malicious project Maintainer may
    create a Project Access Token with Owner level privileges using a crafted request. This is a low severity
    issue (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N, 2.7). It is now mitigated in the latest release and
    is assigned CVE-2023-1084. (CVE-2023-1084)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/03/02/security-release-gitlab-15-9-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56ed9a15");
  # https://vuxml.freebsd.org/freebsd/f7c5b3a9-b9fb-11ed-99c6-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2dd4cee6");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/03");

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
    'gitlab-ce>=15.8.0<15.8.4',
    'gitlab-ce>=15.9.0<15.9.2',
    'gitlab-ce>=9.0.0<15.7.8'
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
