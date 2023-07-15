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
  script_id(147688);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/15");

  script_cve_id("CVE-2020-28413", "CVE-2020-35849");

  script_name(english:"FreeBSD : mantis -- multiple vulnerabilities (2dc8927b-54e0-11eb-9342-1c697a013f4b)");
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
"Mantis 2.24.4 release reports :

Security and maintenance release, addressing 6 CVEs :

- 0027726: CVE-2020-29603: disclosure of private project name

- 0027727: CVE-2020-29605: disclosure of private issue summary

- 0027728: CVE-2020-29604: full disclosure of private issue contents,
including bugnotes and attachments

- 0027361: Private category can be access/used by a non member of a
private project (IDOR)

- 0027779: CVE-2020-35571: XSS in helper_ensure_confirmed() calls

- 0026794: User Account - Takeover

- 0027363: Fixed in version can be changed to a version that doesn't
exist

- 0027350: When updating an issue, a Viewer user can be set as
Reporter

- 0027370: CVE-2020-35849: Revisions allow viewing private bugnotes id
and summary

- 0027495: CVE-2020-28413: SQL injection in the parameter 'access' on
the mc_project_get_users function throught the API SOAP.

- 0027444: Printing unsanitized user input in install.php"
  );
  # https://vuxml.freebsd.org/freebsd/2dc8927b-54e0-11eb-9342-1c697a013f4b.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbf7e055"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mantis-php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mantis-php73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mantis-php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mantis-php80");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"mantis-php72<2.24.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mantis-php73<2.24.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mantis-php74<2.24.4,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mantis-php80<2.24.4,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
