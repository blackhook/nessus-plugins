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

include('compat.inc');

if (description)
{
  script_id(140738);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-15960",
    "CVE-2020-15961",
    "CVE-2020-15962",
    "CVE-2020-15963",
    "CVE-2020-15964",
    "CVE-2020-15965",
    "CVE-2020-15966"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (e68d3db1-fd04-11ea-a67f-e09467587c17)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chrome Releases reports :

This release fixes 10 security issues, including :

- [1100136] High CVE-2020-15960: Out of bounds read in storage.
Reported by Anonymous on 2020-06-28

- [1114636] High CVE-2020-15961: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-08-10

- [1121836] High CVE-2020-15962: Insufficient policy enforcement in
serial. Reported by Leecraso and Guang Gong of 360 Alpha Lab working
with 360 BugCloud on 2020-08-26

- [1113558] High CVE-2020-15963: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-08-06

- [1126249] High CVE-2020-15965: Out of bounds write in V8. Reported
by Lucas Pinheiro, Microsoft Browser Vulnerability Research on
2020-09-08

- [1113565] Medium CVE-2020-15966: Insufficient policy enforcement in
extensions. Reported by David Erceg on 2020-08-06

- [1121414] Low CVE-2020-15964: Insufficient data validation in media.
Reported by Woojin Oh(@pwn_exploit) of STEALIEN on 2020-08-25");
  # https://chromereleases.googleblog.com/2020/09/stable-channel-update-for-desktop_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f96100fb");
  # https://vuxml.freebsd.org/freebsd/e68d3db1-fd04-11ea-a67f-e09467587c17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01c67924");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15965");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<85.0.4183.121")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
