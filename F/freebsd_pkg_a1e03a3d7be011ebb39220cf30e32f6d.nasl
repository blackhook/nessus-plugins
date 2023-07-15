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

include('compat.inc');

if (description)
{
  script_id(146985);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");

  script_name(english:"FreeBSD : salt -- multiple vulnerabilities (a1e03a3d-7be0-11eb-b392-20cf30e32f6d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"SaltStack reports multiple security vulnerabilities in Salt

- CVE-2021-3197: The Salt-API.s SSH client is vulnerable to a shell
injection by including ProxyCommand in an argument, or via ssh_options
provided in an API request.

- CVE-2021-25281: The Salt-API does not have eAuth credentials for the
wheel_async client.

- CVE-2021-25282: The salt.wheel.pillar_roots.write method is
vulnerable to directory traversal.

- CVE-2021-25283: The jinja renderer does not protect against
server-side template injection attacks.

- CVE-2021-25284: webutils write passwords in cleartext to
/var/log/salt/minion

- CVE-2021-3148: command injection in salt.utils.thin.gen_thin()

- CVE-2020-35662: Several places where Salt was not verifying the SSL
cert by default.

- CVE-2021-3144: eauth Token can be used once after expiration.

- CVE-2020-28972: Code base not validating SSL/TLS certificate of the
server, which might allow attackers to obtain sensitive information
via a man-in-the-middle attack

- CVE-2020-28243: Local Privilege Escalation in the Minion.");
  # https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad6e5b97");
  # https://vuxml.freebsd.org/freebsd/a1e03a3d-7be0-11eb-b392-20cf30e32f6d.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ac11567");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-salt-2019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-salt-2019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-salt-2019");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"py36-salt-2019<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt-2019>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt-2019<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt-2019>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt-2019<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt-2019>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-salt>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-salt>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-salt>=3000<3002.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-salt<2019.2.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-salt>=3000<3002.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
