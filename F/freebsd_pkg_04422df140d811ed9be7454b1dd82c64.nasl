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
  script_id(165595);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id(
    "CVE-2022-2882",
    "CVE-2022-2904",
    "CVE-2022-3018",
    "CVE-2022-3060",
    "CVE-2022-3066",
    "CVE-2022-3067",
    "CVE-2022-3279",
    "CVE-2022-3283",
    "CVE-2022-3285",
    "CVE-2022-3286",
    "CVE-2022-3288",
    "CVE-2022-3291",
    "CVE-2022-3293",
    "CVE-2022-3325",
    "CVE-2022-3330",
    "CVE-2022-3351"
  );
  script_xref(name:"IAVA", value:"2022-A-0395-S");
  script_xref(name:"IAVA", value:"2022-A-0456-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple vulnerabilities (04422df1-40d8-11ed-9be7-454b1dd82c64)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 04422df1-40d8-11ed-9be7-454b1dd82c64 advisory.

  - Gitlab reports: Denial of Service via cloning an issue Arbitrary PUT request as victim user through Sentry
    error list Content injection via External Status Checks Project maintainers can access Datadog API Key
    from logs Unsafe serialization of Json data could lead to sensitive data leakage Import bug allows
    importing of private local git repos Maintainer can leak Github access tokens by changing integration URL
    (even after 15.2.1 patch) Unauthorized users able to create issues in any project Bypass group IP
    restriction on Dependency Proxy Healthcheck endpoint allow list can be bypassed when accessed over HTTP in
    an HTTPS enabled system Disclosure of Todo details to guest users A user's primary email may be disclosed
    through group member events webhooks Content manipulation due to branch/tag name confusion with the
    default branch name Leakage of email addresses in WebHook logs Specially crafted output makes job logs
    inaccessible Enforce editing approval rules on project level (CVE-2022-2882, CVE-2022-2904, CVE-2022-3018,
    CVE-2022-3060, CVE-2022-3066, CVE-2022-3067, CVE-2022-3279, CVE-2022-3283, CVE-2022-3285, CVE-2022-3286,
    CVE-2022-3288, CVE-2022-3291, CVE-2022-3293, CVE-2022-3325, CVE-2022-3330, CVE-2022-3351)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2022/09/29/security-release-gitlab-15-4-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c94a2f5");
  # https://vuxml.freebsd.org/freebsd/04422df1-40d8-11ed-9be7-454b1dd82c64.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?846f57de");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3060");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/30");

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
    'gitlab-ce>=15.3.0<15.3.4',
    'gitlab-ce>=15.4.0<15.4.1',
    'gitlab-ce>=9.3.0<15.2.5'
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
