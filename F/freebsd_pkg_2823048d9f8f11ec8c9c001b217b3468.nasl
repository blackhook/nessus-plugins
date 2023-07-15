#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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
  script_id(158782);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2021-4191",
    "CVE-2022-0489",
    "CVE-2022-0549",
    "CVE-2022-0735",
    "CVE-2022-0738",
    "CVE-2022-0741",
    "CVE-2022-0751"
  );

  script_name(english:"FreeBSD : Gitlab -- multiple vulnerabilities (2823048d-9f8f-11ec-8c9c-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2823048d-9f8f-11ec-8c9c-001b217b3468 advisory.

  - Inaccurate display of Snippet files containing special characters in all versions of GitLab CE/EE allows
    an attacker to create Snippets with misleading content which could trick unsuspecting users into executing
    arbitrary commands (CVE-2022-0751)

  - An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8
    to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to
    unauthenticated users through the GraphQL API. (CVE-2021-4191)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting with 8.15 . It was possible
    to trigger a DOS by using the math feature with a specific formula in issue comments. (CVE-2022-0489)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 14.3.6, all versions starting
    from 14.4 before 14.4.4, all versions starting from 14.5 before 14.5.2. Under certain conditions, GitLab
    REST API may allow unprivileged users to add other users to groups even if that is not possible to do
    through the Web UI. (CVE-2022-0549)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.10 before 14.6.5, all
    versions starting from 14.7 before 14.7.4, all versions starting from 14.8 before 14.8.2. An unauthorised
    user was able to steal runner registration tokens through an information disclosure vulnerability using
    quick actions commands. (CVE-2022-0735)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/02/25/critical-security-release-gitlab-14-8-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35c16f9f");
  # https://vuxml.freebsd.org/freebsd/2823048d-9f8f-11ec-8c9c-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?088184ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/10");

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


include("audit.inc");
include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'gitlab-ce>=0<14.6.5',
    'gitlab-ce>=14.7.0<14.7.4',
    'gitlab-ce>=14.8.0<14.8.2'
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
