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
  script_id(137167);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/09");

  script_cve_id("CVE-2020-11008");

  script_name(english:"FreeBSD : malicious URLs can cause git to send a stored credential to wrong server (67765237-8470-11ea-a283-b42e99a1b9c3)");
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
"git security advisory reports :

Git uses external 'credential helper' programs to store and retrieve
passwords or other credentials from secure storage provided by the
operating system. Specially crafted URLs that are considered illegal
as of the recently published Git versions can cause Git to send a
'blank' pattern to helpers, missing hostname and protocol fields. Many
helpers will interpret this as matching any URL, and will return some
unspecified stored password, leaking the password to an attacker's
server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/git/git/security/advisories/GHSA-hjc9-x69f-jqj7"
  );
  # https://vuxml.freebsd.org/freebsd/67765237-8470-11ea-a283-b42e99a1b9c3.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29e88225"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:git-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");
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

if (pkg_test(save_report:TRUE, pkg:"git>=2.26.0<2.26.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.25.0<2.25.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.24.0<2.24.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.23.0<2.23.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.22.0<2.22.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.21.0<2.21.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.20.0<2.20.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.19.0<2.19.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=2.18.0<2.18.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git>=0<2.17.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.26.0<2.26.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.25.0<2.25.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.24.0<2.24.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.23.0<2.23.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.22.0<2.22.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.21.0<2.21.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.20.0<2.20.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.19.0<2.19.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=2.18.0<2.18.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-lite>=0<2.17.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.26.0<2.26.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.25.0<2.25.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.24.0<2.24.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.23.0<2.23.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.22.0<2.22.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.21.0<2.21.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.20.0<2.20.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.19.0<2.19.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=2.18.0<2.18.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"git-gui>=0<2.17.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
