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
  script_id(154774);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-39895",
    "CVE-2021-39897",
    "CVE-2021-39898",
    "CVE-2021-39901",
    "CVE-2021-39902",
    "CVE-2021-39903",
    "CVE-2021-39904",
    "CVE-2021-39905",
    "CVE-2021-39906",
    "CVE-2021-39907",
    "CVE-2021-39909",
    "CVE-2021-39911",
    "CVE-2021-39912",
    "CVE-2021-39913",
    "CVE-2021-39914"
  );
  script_xref(name:"IAVA", value:"2021-A-0523-S");

  script_name(english:"FreeBSD : Gitlab -- Multiple Vulnerabilities (33557582-3958-11ec-90ba-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Gitlab reports :

Stored XSS via ipynb files

Pipeline schedules on imported projects can be set to automatically
active after import

Potential Denial of service via Workhorse

Improper Access Control allows Merge Request creator to bypass locked
status

Projects API discloses ID and name of private groups

Severity of an incident can be changed by a guest user

System root password accidentally written to log file

Potential DoS via a malformed TIFF image

Bypass of CODEOWNERS Merge Request approval requirement

Change project visibility to a restricted option

Project exports leak external webhook token value

SCIM token is visible after creation

Invited group members, with access inherited from parent group,
continue to have project access even after invited subgroup is
transfered

Regular expression denial of service issue when cleaning namespace
path

Prevent creation of scopeless apps using applications API

Webhook data exposes assignee's private email address");
  # https://about.gitlab.com/releases/2021/10/28/security-release-gitlab-14-4-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb58e26d");
  # https://vuxml.freebsd.org/freebsd/33557582-3958-11ec-90ba-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13dc6202");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=14.4.0<14.4.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=14.3.0<14.3.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=0<14.2.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
