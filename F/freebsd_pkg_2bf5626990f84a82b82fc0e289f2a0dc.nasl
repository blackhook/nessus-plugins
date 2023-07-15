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
include('compat.inc');

if (description)
{
  script_id(154925);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-21685",
    "CVE-2021-21686",
    "CVE-2021-21687",
    "CVE-2021-21688",
    "CVE-2021-21689",
    "CVE-2021-21690",
    "CVE-2021-21691",
    "CVE-2021-21692",
    "CVE-2021-21693",
    "CVE-2021-21694",
    "CVE-2021-21695",
    "CVE-2021-21696",
    "CVE-2021-21697",
    "CVE-2021-21698"
  );
  script_xref(name:"IAVA", value:"2021-A-0551-S");

  script_name(english:"FreeBSD : jenkins -- multiple vulnerabilities (2bf56269-90f8-4a82-b82f-c0e289f2a0dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Jenkins Security Advisory : Description(Critical) SECURITY-2455 /
CVE-2021-21685, CVE-2021-21686, CVE-2021-21687, CVE-2021-21688,
CVE-2021-21689, CVE-2021-21690, CVE-2021-21691, CVE-2021-21692,
CVE-2021-21693, CVE-2021-21694, CVE-2021-21695 Multiple
vulnerabilities allow bypassing path filtering of agent-to-controller
access control (High) SECURITY-2423 / CVE-2021-21696
Agent-to-controller access control allowed writing to sensitive
directory used by Pipeline: Shared Groovy Libraries Plugin (High)
SECURITY-2428 / CVE-2021-21697 Agent-to-controller access control
allows reading/writing most content of build directories (Medium)
SECURITY-2506 / CVE-2021-21698 Path traversal vulnerability in
Subversion Plugin allows reading arbitrary files");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2021-11-04/");
  # https://vuxml.freebsd.org/freebsd/2bf56269-90f8-4a82-b82f-c0e289f2a0dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91320c3f");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jenkins-lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"jenkins<2.319")) flag++;
if (pkg_test(save_report:TRUE, pkg:"jenkins-lts<2.303.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
