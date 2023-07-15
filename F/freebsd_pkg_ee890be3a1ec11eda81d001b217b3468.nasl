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
  script_id(170919);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2022-3411",
    "CVE-2022-3759",
    "CVE-2022-4138",
    "CVE-2023-0518"
  );
  script_xref(name:"IAVA", value:"2023-A-0077-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (ee890be3-a1ec-11ed-a81d-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the ee890be3-a1ec-11ed-a81d-001b217b3468 advisory.

  - A lack of length validation in GitLab CE/EE affecting all versions from 12.4 before 15.6.7, 15.7 before
    15.7.6, and 15.8 before 15.8.1 allows an authenticated attacker to create a large Issue description via
    GraphQL which, when repeatedly requested, saturates CPU usage. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H, 6.5). It is now mitigated in the latest release and is
    assigned CVE-2022-3411. (CVE-2022-3411)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.3 before 15.6.7, all
    versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. An attacker may
    upload a crafted CI job artifact zip file in a project that uses dynamic child pipelines and make a
    sidekiq job allocate a lot of memory. In GitLab instances where Sidekiq is memory-limited, this may cause
    Denial of Service. This is a medium severity issue (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L, 4.3). It
    is now mitigated in the latest release and is assigned CVE-2022-3759. (CVE-2022-3759)

  - A Cross Site Request Forgery issue has been discovered in GitLab CE/EE affecting all versions before
    15.6.7, all versions starting from 15.7 before 15.7.6, and all versions starting from 15.8 before 15.8.1.
    An attacker could take over a project if an Owner or Maintainer uploads a file to a malicious project.
    This is a medium severity issue (CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N, 6.4). It is now mitigated
    in the latest release and is assigned CVE-2022-4138. (CVE-2022-4138)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.0 before 15.6.7, all
    versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. It was possible
    to trigger a DoS attack by uploading a malicious Helm chart. This is a medium severity issue
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L, 4.3). It is now mitigated in the latest release and is
    assigned CVE-2023-0518. (CVE-2023-0518)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/01/31/security-release-gitlab-15-8-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c75868d2");
  # https://vuxml.freebsd.org/freebsd/ee890be3-a1ec-11ed-a81d-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77c8aeeb");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/01");

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
    'gitlab-ce>=12.4.0<15.6.7',
    'gitlab-ce>=15.7.0<15.7.6',
    'gitlab-ce>=15.8.0<15.8.1'
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
