#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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
  script_id(92343);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183", "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187", "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217", "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233", "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237", "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241", "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245", "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249");

  script_name(english:"FreeBSD : flash -- multiple vulnerabilities (a522d6ac-4aed-11e6-97ea-002590263bf5)");
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
"Adobe reports :

These updates resolve a race condition vulnerability that could lead
to information disclosure (CVE-2016-4247).

These updates resolve type confusion vulnerabilities that could lead
to code execution (CVE-2016-4223, CVE-2016-4224, CVE-2016-4225).

These updates resolve use-after-free vulnerabilities that could lead
to code execution (CVE-2016-4173, CVE-2016-4174, CVE-2016-4222,
CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229,
CVE-2016-4230, CVE-2016-4231, CVE-2016-4248).

These updates resolve a heap buffer overflow vulnerability that could
lead to code execution (CVE-2016-4249).

These updates resolve memory corruption vulnerabilities that could
lead to code execution (CVE-2016-4172, CVE-2016-4175, CVE-2016-4179,
CVE-2016-4180, CVE-2016-4181, CVE-2016-4182, CVE-2016-4183,
CVE-2016-4184, CVE-2016-4185, CVE-2016-4186, CVE-2016-4187,
CVE-2016-4188, CVE-2016-4189, CVE-2016-4190, CVE-2016-4217,
CVE-2016-4218, CVE-2016-4219, CVE-2016-4220, CVE-2016-4221,
CVE-2016-4233, CVE-2016-4234, CVE-2016-4235, CVE-2016-4236,
CVE-2016-4237, CVE-2016-4238, CVE-2016-4239, CVE-2016-4240,
CVE-2016-4241, CVE-2016-4242, CVE-2016-4243, CVE-2016-4244,
CVE-2016-4245, CVE-2016-4246).

These updates resolve a memory leak vulnerability (CVE-2016-4232).

These updates resolve stack corruption vulnerabilities that could lead
to code execution (CVE-2016-4176, CVE-2016-4177).

These updates resolve a security bypass vulnerability that could lead
to information disclosure (CVE-2016-4178)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html"
  );
  # https://vuxml.freebsd.org/freebsd/a522d6ac-4aed-11e6-97ea-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e172b628"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6_64-flashplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-f10-flashplugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"linux-c6-flashplugin<11.2r202.632")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6_64-flashplugin<11.2r202.632")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-f10-flashplugin<11.2r202.632")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
