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
  script_id(173722);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2022-3375",
    "CVE-2022-3513",
    "CVE-2023-0155",
    "CVE-2023-0319",
    "CVE-2023-0450",
    "CVE-2023-0485",
    "CVE-2023-0523",
    "CVE-2023-0838",
    "CVE-2023-1071",
    "CVE-2023-1098",
    "CVE-2023-1167",
    "CVE-2023-1417",
    "CVE-2023-1708",
    "CVE-2023-1710",
    "CVE-2023-1733"
  );
  script_xref(name:"IAVA", value:"2023-A-0168-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (54006796-cf7b-11ed-a5d5-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 54006796-cf7b-11ed-a5d5-001b217b3468 advisory.

  - Gitlab reports: Cross-site scripting in Maximum page reached page Private project guests can read new
    changes using a fork Mirror repository error reveals password in Settings UI DOS and high resource
    consumption of Prometheus server through abuse of Prometheus integration proxy endpoint Unauthenticated
    users can view Environment names from public projects limited to project members only Copying information
    to the clipboard could lead to the execution of unexpected commands Maintainer can leak masked webhook
    secrets by adding a new parameter to the webhook URL Arbitrary HTML injection possible when
    :soft_email_confirmation feature flag is enabled in the latest release Framing of arbitrary content
    (leading to open redirects) on any page allowing user controlled markdown MR for security reports are
    available to everyone API timeout when searching for group issues Unauthorised user can add child epics
    linked to victim's epic in an unrelated group GitLab search allows to leak internal notes Ambiguous branch
    name exploitation in GitLab Improper permissions checks for moving an issue Private project branches names
    can be leaked through a fork (CVE-2022-3375, CVE-2022-3513, CVE-2023-0155)

  - An issue has been discovered in GitLab affecting all versions starting from 13.6 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10  before 15.10.1, allowing
    reading of environment names supposed to be restricted to project members only. This is a medium severity
    issue (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N, 5.8). It is now mitigated in the latest release and
    is assigned CVE-2023-0319. (CVE-2023-0319)

  - An issue has been discovered in GitLab affecting all versions starting from 8.1 to 15.8.5, and from 15.9
    to 15.9.4, and from 15.10 to 15.10.1. It was possible to add a branch with an ambiguous name that could be
    used to social engineer users. This is a low severity issue (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N,
    3.7). It is now mitigated in the latest release and is assigned CVE-2023-0450. (CVE-2023-0450)

  - An issue has been discovered in GitLab affecting all versions starting from 13.11 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10  before 15.10.1. It was
    possible that a project member demoted to a user role could read project updates by doing a diff with a
    pre-existing fork. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N, 6.5). It
    is now mitigated in the latest release and is assigned CVE-2023-0485. (CVE-2023-0485)

  - An issue has been discovered in GitLab affecting all versions starting from 15.6 before 15.8.5, 15.9
    before 15.9.4, and 15.10 before 15.10.1. On certain instances, a stored XSS was possible via a malicious
    email address, which only affected the admins when they tried to impersonate the account with the
    malicious payload. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N, 5.4). It
    is now mitigated in the latest release and is assigned CVE-2023-0523. (CVE-2023-0523)

  - An issue has been discovered in GitLab affecting versions starting from 15.1 before 15.8.5, 15.9 before
    15.9.4, and 15.10 before 15.10.1. A maintainer could modify a webhook URL to leak masked webhook secrets
    by adding a new parameter to the url. This addresses an incomplete fix for CVE-2022-4342. This is a medium
    severity issue (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N, 5.5). It is now mitigated in the latest
    release and is assigned CVE-2023-0838. (CVE-2023-0838)

  - An issue has been discovered in GitLab affecting all versions from 15.5 before 15.8.5, all versions
    starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1. Due to improper
    permissions checks it was possible for an unauthorised user to remove an issue from an epic. This is a low
    severity issue (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N, 3.1). It is now mitigated in the latest
    release and is assigned CVE-2023-1071. (CVE-2023-1071)

  - An information disclosure vulnerability has been discovered in GitLab EE/CE affecting all versions
    starting from 11.5 before 15.8.5, all versions starting from 15.9 before 15.9.4, all  versions starting
    from 15.10  before 15.10.1 will allow an admin to leak password from repository mirror configuration. This
    is a medium severity issue (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N, 5.8). It is now mitigated in the
    latest release and is assigned CVE-2023-1098. (CVE-2023-1098)

  - Improper authorization in GitLab EE affecting all versions from 12.3.0 before 15.8.5, all versions
    starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1 allows an unauthorized
    access to security reports in merge requests. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, 5.3). It is now mitigated in the latest release and is
    assigned CVE-2023-1167. (CVE-2023-1167)

  - An issue has been discovered in GitLab affecting all versions starting from 15.9 before 15.9.4, all
    versions starting from 15.10  before 15.10.1. It was possible for an unauthorised user to add child epics
    linked to a victim's epic in an unrelated group. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N, 4.3). It is now mitigated in the latest release and is
    assigned CVE-2023-1417. (CVE-2023-1417)

  - An issue was identified in GitLab CE/EE affecting all versions from 1.0 prior to 15.8.5, 15.9 prior to
    15.9.4, and 15.10 prior to 15.10.1 where non-printable characters are copied from clipboard, allowing
    unexpected commands to be executed on the victim machine. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N, 5.7). It is now mitigated in the latest release and is
    assigned CVE-2023-1708. (CVE-2023-1708)

  - A sensitive information disclosure vulnerability in GitLab affecting all versions from 15.0 prior to
    15.8.5, 15.9 prior to 15.9.4 and 15.10 prior to 15.10.1 allows an attacker to view the count of internal
    notes for a given issue. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N,
    5.3). It is now mitigated in the latest release and is assigned CVE-2023-1710 (CVE-2023-1710)

  - A denial of service condition exists in the Prometheus server bundled with GitLab affecting all versions
    from 11.10 to 15.8.5, 15.9 to 15.9.4 and 15.10 to 15.10.1. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L, 5.8). It is now mitigated in the latest release and is
    assigned CVE-2023-1733. (CVE-2023-1733)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/03/30/security-release-gitlab-15-10-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43e3f19d");
  # https://vuxml.freebsd.org/freebsd/54006796-cf7b-11ed-a5d5-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70e347ee");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/31");

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
    'gitlab-ce>=15.10.0<15.10.1',
    'gitlab-ce>=15.9.0<15.9.4',
    'gitlab-ce>=8.1<15.8.5'
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
