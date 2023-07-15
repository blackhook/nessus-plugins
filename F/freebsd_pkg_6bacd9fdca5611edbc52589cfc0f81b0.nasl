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
  script_id(173401);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/24");

  script_name(english:"FreeBSD : phpmyfaq -- multiple vulnerabilities (6bacd9fd-ca56-11ed-bc52-589cfc0f81b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 6bacd9fd-ca56-11ed-bc52-589cfc0f81b0 advisory.

  - phpmyfaq developers report: XSS weak passwords privilege escalation Captcha bypass (6bacd9fd-ca56-11ed-
    bc52-589cfc0f81b0)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/01d6ae23-3a8f-42a8-99f4-10246187d71b/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/0854328e-eb00-41a3-9573-8da8f00e369c/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/1dc7f818-c8ea-4f80-b000-31b48a426334/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/24c0a65f-0751-4ff8-af63-4b325ac8879f/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/2d0ac48a-490d-4548-8d98-7447042dd1b5/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/2f1e417d-cf64-4cfb-954b-3a9cb2f38191/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/39715aaf-e798-4c60-97c4-45f4f2cd5c61/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/3c2374cc-7082-44b7-a6a6-ccff7a650a3a/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/529f2361-eb2e-476f-b7ef-4e561a712e28/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/584a200a-6ff8-4d53-a3c0-e7893edff60c/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/882ffa07-5397-4dbb-886f-4626859d711a/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/8ab09a1c-cfd5-4ce0-aae3-d33c93318957/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/93f981a3-231d-460d-a239-bb960e8c2fdc/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/b7d244b7-5ac3-4964-81ee-8dbb5bb5e33a/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/bce84c02-abb2-474f-a67b-1468c9dcabb8/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/dda73cb6-9344-4822-97a1-2e31efb6a73e/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/e495b443-b328-42f5-aed5-d68b929b4cb9/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/e4a58835-96b5-412c-a17e-3ceed30231e1/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/e8109aed-d364-4c0c-9545-4de0347b10e1/");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/ece5f051-674e-4919-b998-594714910f9e/");
  # https://vuxml.freebsd.org/freebsd/6bacd9fd-ca56-11ed-bc52-589cfc0f81b0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4381339");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/24");

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
    'phpmyfaq<3.1.12'
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
