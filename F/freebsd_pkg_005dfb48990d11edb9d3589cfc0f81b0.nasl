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
  script_id(170207);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_name(english:"FreeBSD : phpmyfaq -- multiple vulnerabilities (005dfb48-990d-11ed-b9d3-589cfc0f81b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 005dfb48-990d-11ed-b9d3-589cfc0f81b0 advisory.

  - phpmyfaq developers report: phpMyFAQ does not implement sufficient checks to avoid a stored
    XSS in Add new question phpMyFAQ does not implement sufficient checks to avoid a stored XSS
    in admin user page phpMyFAQ does not implement sufficient checks to avoid a stored XSS             in FAQ
    comments phpMyFAQ does not implement sufficient checks to avoid a blind             stored XSS in admin
    open question page phpMyFAQ does not implement sufficient checks to avoid a reflected             XSS in
    the admin backend login phpMyFAQ does not implement sufficient checks to avoid stored XSS             on
    user, category, FAQ, news and configuration admin backend phpMyFAQ does not implement sufficient checks to
    avoid weak passwords (005dfb48-990d-11ed-b9d3-589cfc0f81b0)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/051d5e20-7fab-4769-bd7d-d986b804bb5a/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/82b0b629-c56b-4651-af3f-17f749751857/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/83cfed62-af8b-4aaa-94f2-5a33dc0c2d69/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/bc27e84b-1f91-4e1b-a78c-944edeba8256/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/c03c5925-43ff-450d-9827-2b65a3307ed6/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/cbba22f0-89ed-4d01-81ea-744979c8cbde/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/eac0a9d7-9721-4191-bef3-d43b0df59c67/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/f50ec8d1-cd60-4c2d-9ab8-3711870d83b9/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/fac01e9f-e3e5-4985-94ad-59a76485f215/");
  # https://vuxml.freebsd.org/freebsd/005dfb48-990d-11ed-b9d3-589cfc0f81b0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c206cd59");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'phpmyfaq<3.1.10'
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
