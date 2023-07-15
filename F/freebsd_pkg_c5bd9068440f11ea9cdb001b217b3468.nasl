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
  script_id(133434);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2019-16779", "CVE-2019-16892", "CVE-2019-18978", "CVE-2020-6833", "CVE-2020-7966", "CVE-2020-7967", "CVE-2020-7968", "CVE-2020-7969", "CVE-2020-7971", "CVE-2020-7972", "CVE-2020-7973", "CVE-2020-7974", "CVE-2020-7976", "CVE-2020-7977", "CVE-2020-7978", "CVE-2020-7979", "CVE-2020-8114");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (c5bd9068-440f-11ea-9cdb-001b217b3468)");
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

Path Traversal to Arbitrary File Read

User Permissions Not Validated in ProjectExportWorker

XSS Vulnerability in File API

Package and File Disclosure through GitLab Workhorse

XSS Vulnerability in Create Groups

Issue and Merge Request Activity Counts Exposed

Email Confirmation Bypass Using AP

Disclosure of Forked Private Project Source Code

Private Project Names Exposed in GraphQL queries

Disclosure of Issues and Merge Requests via Todos

Denial of Service via AsciiDoc

Last Pipeline Status Exposed

Arbitrary Change of Pipeline Status

Grafana Token Displayed in Plaintext

Update excon gem

Update rdoc gem

Update rack-cors gem

Update rubyzip gem"
  );
  # https://about.gitlab.com/releases/2020/01/30/security-release-gitlab-12-7-4-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c01373b"
  );
  # https://vuxml.freebsd.org/freebsd/c5bd9068-440f-11ea-9cdb-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ab7b29f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8114");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=12.7.0<12.7.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=12.6.0<12.6.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=5.3<12.5.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
