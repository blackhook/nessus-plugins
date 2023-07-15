#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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
include("compat.inc");

if (description)
{
  script_id(153870);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/14");

  script_cve_id("CVE-2021-22259", "CVE-2021-39866", "CVE-2021-39867", "CVE-2021-39868", "CVE-2021-39869", "CVE-2021-39870", "CVE-2021-39871", "CVE-2021-39872", "CVE-2021-39873", "CVE-2021-39874", "CVE-2021-39875", "CVE-2021-39877", "CVE-2021-39878", "CVE-2021-39879", "CVE-2021-39881", "CVE-2021-39882", "CVE-2021-39883", "CVE-2021-39884", "CVE-2021-39885", "CVE-2021-39886", "CVE-2021-39887");

  script_name(english:"FreeBSD : Gitlab -- vulnerabilities (1bdd4db6-2223-11ec-91be-001b217b3468)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Gitlab reports :

Stored XSS in merge request creation page

Denial-of-service attack in Markdown parser

Stored Cross-Site Scripting vulnerability in the GitLab Flavored
Markdown

DNS Rebinding vulnerability in Gitea importer

Exposure of trigger tokens on project exports

Improper access control for users with expired password

Access tokens are not cleared after impersonation

Reflected Cross-Site Scripting in Jira Integration

DNS Rebinding vulnerability in Fogbugz importer

Access tokens persist after project deletion

User enumeration vulnerability

Potential DOS via API requests

Pending invitations of public groups and public projects are visible
to any user

Bypass Disabled Repo by URL Project Creation

Low privileged users can see names of the private groups shared in
projects

API discloses sensitive info to low privileged users

Epic listing do not honour group memberships

Insecure Direct Object Reference vulnerability may lead to protected
branch names getting disclosed

Low privileged users can import users from projects that they they are
not a maintainer on

Potential DOS via dependencies API

Create a project with unlimited repository size through malicious
Project Import

Bypass disabled Bitbucket Server import source project creation

Requirement to enforce 2FA is not honored when using git commands

Content spoofing vulnerability

Improper session management in impersonation feature

Create OAuth application with arbitrary scopes through content
spoofing

Lack of account lockout on change password functionality

Epic reference was not updated while moved between groups

Missing authentication allows disabling of two-factor authentication

Information disclosure in SendEntry"
  );
  # https://about.gitlab.com/releases/2021/09/30/security-release-gitlab-14-3-1-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54becce3"
  );
  # https://vuxml.freebsd.org/freebsd/1bdd4db6-2223-11ec-91be-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1440361c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39867");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=14.3.0<14.3.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=14.2.0<14.2.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=0<14.1.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
