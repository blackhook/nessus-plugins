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
  script_id(165288);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-35957");

  script_name(english:"FreeBSD : Grafana -- Privilege escalation (95e6e6ca-3986-11ed-8e0c-6c3be5272acd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 95e6e6ca-3986-11ed-8e0c-6c3be5272acd advisory.

  - Grafana is an open-source platform for monitoring and observability. Versions prior to 9.1.6 and 8.5.13
    are vulnerable to an escalation from admin to server admin when auth proxy is used, allowing an admin to
    take over the server admin account and gain full control of the grafana instance. All installations should
    be upgraded as soon as possible. As a workaround deactivate auth proxy following the instructions at:
    https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-
    proxy/ (CVE-2022-35957)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/grafana/grafana/security/advisories/GHSA-ff5c-938w-8c9q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3633536");
  # https://vuxml.freebsd.org/freebsd/95e6e6ca-3986-11ed-8e0c-6c3be5272acd.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86e0023a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:grafana9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
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
    'grafana8>=8.0.0<8.5.13',
    'grafana9>=9.0.0<9.0.9',
    'grafana9>=9.1.0<9.1.6',
    'grafana>=2.1.0<8.5.13',
    'grafana>=9.0.0<9.0.9',
    'grafana>=9.1.0<9.1.6'
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
