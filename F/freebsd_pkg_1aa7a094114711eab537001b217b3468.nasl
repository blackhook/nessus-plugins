#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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

include("compat.inc");

if (description)
{
  script_id(131466);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/08");

  script_cve_id("CVE-2019-19086", "CVE-2019-19087", "CVE-2019-19088", "CVE-2019-19254", "CVE-2019-19255", "CVE-2019-19256", "CVE-2019-19257", "CVE-2019-19258", "CVE-2019-19259", "CVE-2019-19260", "CVE-2019-19261", "CVE-2019-19262", "CVE-2019-19263", "CVE-2019-19309", "CVE-2019-19310", "CVE-2019-19311", "CVE-2019-19312", "CVE-2019-19313", "CVE-2019-19314");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (1aa7a094-1147-11ea-b537-001b217b3468)");
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

Path traversal with potential remote code execution

Private objects exposed through project import

Disclosure of notes via Elasticsearch integration

Disclosure of comments via Elasticsearch integration

DNS Rebind SSRF in various chat notifications

Disclosure of vulnerability status in dependency list

Disclosure of commit count in Cycle Analytics

Exposure of related branch names

Tags pushes from blocked users

Branches and Commits exposed to Guest members via integration

IDOR when adding users to protected environments

Former project members able to access repository information

Unauthorized access to grafana metrics

Todos created for former project members

Update Mattermost dependency

Disclosure of AWS secret keys on certain Admin pages

Stored XSS in Group and User profile fields

Forked project information disclosed via Project API

Denial of Service in the issue and commit comment pages

Tokens stored in plaintext"
  );
  # https://about.gitlab.com/blog/2019/11/27/security-release-gitlab-12-5-1-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4cf08a8c"
  );
  # https://vuxml.freebsd.org/freebsd/1aa7a094-1147-11ea-b537-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?896288a7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19088");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=12.5.0<12.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=12.4.0<12.4.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce<12.3.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
