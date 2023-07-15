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
  script_id(169892);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3514",
    "CVE-2022-3573",
    "CVE-2022-3613",
    "CVE-2022-3870",
    "CVE-2022-4037",
    "CVE-2022-4131",
    "CVE-2022-4167",
    "CVE-2022-4342",
    "CVE-2022-4365",
    "CVE-2023-0042"
  );
  script_xref(name:"IAVA", value:"2023-A-0032-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (3a023570-91ab-11ed-8950-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 3a023570-91ab-11ed-8950-001b217b3468 advisory.

  - Incorrect Authorization check affecting all versions of GitLab EE from 13.11 prior to 15.5.7, 15.6 prior
    to 15.6.4, and 15.7 prior to 15.7.2 allows group access tokens to continue working even after the group
    owner loses the ability to revoke them. (CVE-2022-4167)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 6.6 before 15.5.7, all
    versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. An attacker may
    cause Denial of Service on a GitLab instance by exploiting a regex issue in the submodule URL parser.
    (CVE-2022-3514)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.4 before 15.5.7, all
    versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. Due to the
    improper filtering of query parameters in the wiki changes page, an attacker can execute arbitrary
    JavaScript on the self-hosted instances running without strict CSP. (CVE-2022-3573)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 15.5.7, all versions starting
    from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. A crafted Prometheus Server query
    can cause high resource consumption and may lead to Denial of Service. (CVE-2022-3613)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.0 before 15.5.7, all
    versions starting from 15.6 before 15.6.4, all versions starting from 15.7 before 15.7.2. GitLab allows
    unauthenticated users to download user avatars using the victim's user ID, on private instances that
    restrict public level visibility. (CVE-2022-3870)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/01/09/security-release-gitlab-15-7-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6dc25fe");
  # https://vuxml.freebsd.org/freebsd/3a023570-91ab-11ed-8950-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d758eee");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4167");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

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
    'gitlab-ce>=15.6.0<15.6.4',
    'gitlab-ce>=15.7.0<15.7.2',
    'gitlab-ce>=6.6.0<15.5.7'
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
