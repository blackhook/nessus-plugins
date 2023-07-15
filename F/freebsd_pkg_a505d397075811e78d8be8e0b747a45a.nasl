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
  script_id(97689);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2017-5029",
    "CVE-2017-5030",
    "CVE-2017-5031",
    "CVE-2017-5032",
    "CVE-2017-5033",
    "CVE-2017-5034",
    "CVE-2017-5035",
    "CVE-2017-5036",
    "CVE-2017-5037",
    "CVE-2017-5038",
    "CVE-2017-5039",
    "CVE-2017-5040",
    "CVE-2017-5041",
    "CVE-2017-5042",
    "CVE-2017-5043",
    "CVE-2017-5044",
    "CVE-2017-5045",
    "CVE-2017-5046"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (a505d397-0758-11e7-8d8b-e8e0b747a45a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Google Chrome Releases reports :

36 security fixes in this release

Please reference CVE/URL list for details");
  # https://chromereleases.googleblog.com/2017/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d061769");
  # https://vuxml.freebsd.org/freebsd/a505d397-0758-11e7-8d8b-e8e0b747a45a.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86b96e4a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-npapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium-pulse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<57.0.2987.98")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-npapi<57.0.2987.98")) flag++;
if (pkg_test(save_report:TRUE, pkg:"chromium-pulse<57.0.2987.98")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
