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
  script_id(168666);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_name(english:"FreeBSD : phpmyfaq -- multiple vulnerabilities (439f3f81-7a49-11ed-97ac-589cfc0f81b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 439f3f81-7a49-11ed-97ac-589cfc0f81b0 advisory.

  - phpmyfaq developers report: an authenticated SQL injection when adding categories in the admin backend a
    stored cross-site scripting vulnerability in the category name a stored cross-site scripting vulnerability
    in the admin logging a stored cross-site scripting vulnerability in the FAQ title a PostgreSQL based SQL
    injection for the lang parameter  a SQL injection when storing an instance name in the admin backend a SQL
    injection when adding attachments in the admin backend a stored cross-site scripting vulnerability when
    adding users by admins a missing secure flag for cookies when using TLS a cross-site request forgery /
    cross-site scripting vulnerability when saving new questions a reflected cross-site scripting
    vulnerability in the admin backend (439f3f81-7a49-11ed-97ac-589cfc0f81b0)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/2ec4ddd4-de22-4f2d-ba92-3382b452bfea/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/315aa78d-7bd2-4b14-86f2-b5c211e62034/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/322c12b1-08d5-4ee3-9d94-d4bb40366c7a/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/56499a60-2358-41fe-9b38-8cb23cdfc17c/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/5915ed4c-5fe2-42e7-8fac-5dd0d032727c/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/5944f154-c0ab-4547-9d9d-3101e86eb975/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/a1649f43-78c9-4927-b313-36911872a84b/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/eb3a8ea3-daea-4555-a3e6-80b82f533792/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/f2857bc7-8fbc-489a-9a38-30b93300eec5/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/f531bbf2-32c8-4efe-8156-ae9bc6b5d3aa/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/faac0c92-8d4b-4901-a933-662b661a3f99/");
  # https://vuxml.freebsd.org/freebsd/439f3f81-7a49-11ed-97ac-589cfc0f81b0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946bbd7c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'phpmyfaq<3.1.9'
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
