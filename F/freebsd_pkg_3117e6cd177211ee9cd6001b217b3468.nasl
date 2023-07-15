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
  script_id(177846);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-1936",
    "CVE-2023-2190",
    "CVE-2023-2200",
    "CVE-2023-2576",
    "CVE-2023-2620",
    "CVE-2023-3102",
    "CVE-2023-3362",
    "CVE-2023-3363",
    "CVE-2023-3424",
    "CVE-2023-3444"
  );
  script_xref(name:"IAVA", value:"2023-A-0327");

  script_name(english:"FreeBSD : Gitlab -- Vulnerabilities (3117e6cd-1772-11ee-9cd6-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 3117e6cd-1772-11ee-9cd6-001b217b3468 advisory.

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.7 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1, which allows
    an attacker to leak the email address of a user who created a service desk issue. (CVE-2023-1936)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.10 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1. It may be
    possible for users to view new commits to private projects in a fork created while the project was public.
    (CVE-2023-2190)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 7.14 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1, which allows
    an attacker to inject HTML in an email address field. (CVE-2023-2200)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.7 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1. This allowed
    a developer to remove the CODEOWNERS rules and merge to a protected branch. (CVE-2023-2576)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.1 prior to 15.11.10,
    all versions from 16.0 prior to 16.0.6, all versions from 16.1 prior to 16.1.1. A maintainer could modify
    a webhook URL to leak masked webhook secrets by manipulating other masked portions. This addresses an
    incomplete fix for CVE-2023-0838. (CVE-2023-2620)

  - A sensitive information leak issue has been discovered in GitLab EE affecting all versions starting from
    16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1, which allows access to titles of
    private issues and merge requests. (CVE-2023-3102)

  - An information disclosure issue in GitLab CE/EE affecting all versions from 16.0 prior to 16.0.6, and
    version 16.1.0 allows unauthenticated actors to access the import error information if a project was
    imported from GitHub. (CVE-2023-3362)

  - An information disclosure issue in Gitlab CE/EE affecting all versions from 13.6 prior to 15.11.10, all
    versions from 16.0 prior to 16.0.6, all versions from 16.1 prior to 16.1.1, resulted in the Sidekiq log
    including webhook tokens when the log format was set to default. (CVE-2023-3363)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.3 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1. A Regular
    Expression Denial of Service was possible via sending crafted payloads to the preview_markdown endpoint.
    (CVE-2023-3424)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.3 before 15.11.10,
    all versions starting from 16.0 before 16.0.6, all versions starting from 16.1 before 16.1.1, which allows
    an attacker to merge arbitrary code into protected branches due to a CODEOWNERS approval bug.
    (CVE-2023-3444)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/06/29/security-release-gitlab-16-1-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a8ab2a0");
  # https://vuxml.freebsd.org/freebsd/3117e6cd-1772-11ee-9cd6-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7e64bee");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2190");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

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
    'gitlab-ce>=15.11.0<15.11.10',
    'gitlab-ce>=16.0.0<16.0.6',
    'gitlab-ce>=16.1.0<16.1.1',
    'gitlab-ce>=7.14.0<15.10.8'
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
