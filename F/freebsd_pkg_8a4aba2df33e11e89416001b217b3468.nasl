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

include("compat.inc");

if (description)
{
  script_id(119271);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2018-19493", "CVE-2018-19494", "CVE-2018-19495", "CVE-2018-19496", "CVE-2018-19569", "CVE-2018-19570", "CVE-2018-19571", "CVE-2018-19572", "CVE-2018-19573", "CVE-2018-19574", "CVE-2018-19575", "CVE-2018-19576", "CVE-2018-19577", "CVE-2018-19578", "CVE-2018-19579", "CVE-2018-19580", "CVE-2018-19581", "CVE-2018-19582", "CVE-2018-19583", "CVE-2018-19584", "CVE-2018-19585");

  script_name(english:"FreeBSD : Gitlab -- Multiple vulnerabilities (8a4aba2d-f33e-11e8-9416-001b217b3468)");
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

View Names of Private Groups

Persistent XSS in Environments

SSRF in Prometheus integration

Unauthorized Promotion of Milestones

Exposure of Confidential Issue Title

Persisent XSS in Markdown Fields via Mermaid Script

Persistent XSS in Markdown Fields via Unrecognized HTML Tags

Symlink Race Condition in Pages

Unauthorized Changes by Guest User in Issues

Unauthorized Comments on Locked Issues

Improper Enforcement of Token Scope

CRLF Injection in Project Mirroring

XSS in OAuth Authorization

SSRF in Webhooks

Send Email on Email Address Change

Workhorse Logs Contained Tokens

Unauthorized Publishing of Draft Comments

Guest Can Set Weight of a New Issue

Disclosure of Private Group's Members and Milestones

Persisent XSS in Operations

Reporter Can View Operations Page"
  );
  # https://about.gitlab.com/2018/11/28/security-release-gitlab-11-dot-5-dot-1-released/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?974abfc1"
  );
  # https://vuxml.freebsd.org/freebsd/8a4aba2d-f33e-11e8-9416-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08e10f75"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.5.0<11.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.4.0<11.4.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=0<11.3.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
