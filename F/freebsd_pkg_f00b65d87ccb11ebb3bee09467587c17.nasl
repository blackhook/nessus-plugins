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
  script_id(147152);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-27844",
    "CVE-2021-21159",
    "CVE-2021-21160",
    "CVE-2021-21161",
    "CVE-2021-21162",
    "CVE-2021-21163",
    "CVE-2021-21164",
    "CVE-2021-21165",
    "CVE-2021-21166",
    "CVE-2021-21167",
    "CVE-2021-21168",
    "CVE-2021-21169",
    "CVE-2021-21170",
    "CVE-2021-21171",
    "CVE-2021-21172",
    "CVE-2021-21173",
    "CVE-2021-21174",
    "CVE-2021-21175",
    "CVE-2021-21176",
    "CVE-2021-21177",
    "CVE-2021-21178",
    "CVE-2021-21179",
    "CVE-2021-21180",
    "CVE-2021-21181",
    "CVE-2021-21182",
    "CVE-2021-21183",
    "CVE-2021-21184",
    "CVE-2021-21185",
    "CVE-2021-21186",
    "CVE-2021-21187",
    "CVE-2021-21188",
    "CVE-2021-21189",
    "CVE-2021-21190"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (f00b65d8-7ccb-11eb-b3be-e09467587c17)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release includes 47 security fixes, including the below. Google
is aware of reports that an exploit for CVE-2021-21166 exists in the
wild. Please see URL for details.");
  # https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc64b00e");
  # https://vuxml.freebsd.org/freebsd/f00b65d8-7ccb-11eb-b3be-e09467587c17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b92bef2");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27844");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21190");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<89.0.4389.72")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
