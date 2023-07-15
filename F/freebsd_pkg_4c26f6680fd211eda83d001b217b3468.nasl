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
  script_id(163649);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id(
    "CVE-2022-2095",
    "CVE-2022-2303",
    "CVE-2022-2307",
    "CVE-2022-2326",
    "CVE-2022-2417",
    "CVE-2022-2456",
    "CVE-2022-2459",
    "CVE-2022-2497",
    "CVE-2022-2498",
    "CVE-2022-2499",
    "CVE-2022-2500",
    "CVE-2022-2501",
    "CVE-2022-2512",
    "CVE-2022-2531",
    "CVE-2022-2534",
    "CVE-2022-2539"
  );
  script_xref(name:"IAVA", value:"2022-A-0302-S");

  script_name(english:"FreeBSD : Gitlab -- multiple vulnerabilities (4c26f668-0fd2-11ed-a83d-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 4c26f668-0fd2-11ed-a83d-001b217b3468 advisory.

  - Gitlab reports: Revoke access to confidential notes todos Pipeline subscriptions trigger new pipelines
    with the wrong author Ability to gain access to private project through an email invite by using other
    user's email address as an unverified secondary email Import via git protocol allows to bypass checks on
    repository Unauthenticated IP allowlist bypass when accessing job artifacts through GitLab Pages
    Maintainer can leak Packagist and other integration access tokens by changing integration URL
    Unauthenticated access to victims Grafana datasources through path traversal Unauthorized users can filter
    issues by contact and organization Malicious Maintainer may change the visibility of project or a group
    Stored XSS in job error messages Enforced group MFA can be bypassed when using Resource Owner Password
    Credentials grant Non project members can view public project's Deploy Keys IDOR in project with Jira
    integration leaks project owner's other projects Jira issues Group Bot Users and Tokens not deleted after
    group deletion Email invited members can join projects even after the member lock has been enabled Datadog
    integration returns user emails (CVE-2022-2095, CVE-2022-2303, CVE-2022-2307, CVE-2022-2326,
    CVE-2022-2417, CVE-2022-2456, CVE-2022-2459, CVE-2022-2497, CVE-2022-2498, CVE-2022-2499, CVE-2022-2500,
    CVE-2022-2501, CVE-2022-2512, CVE-2022-2531, CVE-2022-2534, CVE-2022-2539)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/07/28/security-release-gitlab-15-2-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d76f33e");
  # https://vuxml.freebsd.org/freebsd/4c26f668-0fd2-11ed-a83d-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a32776e7");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2326");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/30");

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
    'gitlab-ce>=0<15.0.5',
    'gitlab-ce>=15.1.0<15.1.4',
    'gitlab-ce>=15.2.0<15.2.1'
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
