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
  script_id(136849);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-6465",
    "CVE-2020-6466",
    "CVE-2020-6467",
    "CVE-2020-6468",
    "CVE-2020-6469",
    "CVE-2020-6470",
    "CVE-2020-6471",
    "CVE-2020-6472",
    "CVE-2020-6473",
    "CVE-2020-6474",
    "CVE-2020-6475",
    "CVE-2020-6476",
    "CVE-2020-6477",
    "CVE-2020-6478",
    "CVE-2020-6479",
    "CVE-2020-6480",
    "CVE-2020-6481",
    "CVE-2020-6482",
    "CVE-2020-6483",
    "CVE-2020-6484",
    "CVE-2020-6485",
    "CVE-2020-6486",
    "CVE-2020-6487",
    "CVE-2020-6488",
    "CVE-2020-6489",
    "CVE-2020-6490",
    "CVE-2020-6491"
  );

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (38c676bd-9def-11ea-a94c-3065ec8fd3ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Google Chrome Releases reports :

This release includes 38 security fixes, including CVEs CVE-2020-6465
through CVE-2020-6491.");
  # https://chromereleases.googleblog.com/2020/05/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26bb137e");
  # https://vuxml.freebsd.org/freebsd/38c676bd-9def-11ea-a94c-3065ec8fd3ec.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?709276be");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6474");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

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

if (pkg_test(save_report:TRUE, pkg:"chromium<83.0.4103.61")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
