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
  script_id(156031);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-39910",
    "CVE-2021-39915",
    "CVE-2021-39916",
    "CVE-2021-39917",
    "CVE-2021-39918",
    "CVE-2021-39919",
    "CVE-2021-39930",
    "CVE-2021-39931",
    "CVE-2021-39932",
    "CVE-2021-39933",
    "CVE-2021-39934",
    "CVE-2021-39935",
    "CVE-2021-39936",
    "CVE-2021-39937",
    "CVE-2021-39938",
    "CVE-2021-39940",
    "CVE-2021-39941",
    "CVE-2021-39944",
    "CVE-2021-39945"
  );

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (b299417a-5725-11ec-a587-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the b299417a-5725-11ec-a587-001b217b3468 advisory.

  - Improper access control in the GitLab CE/EE API affecting all versions starting from 9.4 before 14.3.6,
    all versions starting from 14.4 before 14.4.4, all versions starting from 14.5 before 14.5.2, allows an
    author of a Merge Request to approve the Merge Request even after having their project access revoked
    (CVE-2021-39945)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.6 before 14.3.6, all
    versions starting from 14.4 before 14.4.4, all versions starting from 14.5 before 14.5.2. GitLab was
    vulnerable to HTML Injection through the Swagger UI feature. (CVE-2021-39910)

  - Improper access control in the GraphQL API in GitLab CE/EE affecting all versions starting from 13.0
    before 14.3.6, all versions starting from 14.4 before 14.4.4, all versions starting from 14.5 before
    14.5.2, allows an attacker to see the names of project access tokens on arbitrary projects
    (CVE-2021-39915)

  - Lack of an access control check in the External Status Check feature allowed any authenticated user to
    retrieve the configuration of any External Status Check in GitLab EE starting from 14.1 before 14.3.6, all
    versions starting from 14.4 before 14.4.4, all versions starting from 14.5 before 14.5.2. (CVE-2021-39916)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.9 before 14.3.6, all
    versions starting from 14.4 before 14.4.4, all versions starting from 14.5 before 14.5.2. A regular
    expression related to quick actions features was susceptible to catastrophic backtracking that could cause
    a DOS attack. (CVE-2021-39917)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2021/12/06/security-release-gitlab-14-5-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d8f7e78");
  # https://vuxml.freebsd.org/freebsd/b299417a-5725-11ec-a587-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56c1d2cc");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'gitlab-ce>=0<14.3.6',
    'gitlab-ce>=14.4.0<14.4.4',
    'gitlab-ce>=14.5.0<14.5.2'
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
