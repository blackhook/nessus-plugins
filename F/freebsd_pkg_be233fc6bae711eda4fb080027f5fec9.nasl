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
  script_id(172104);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2023-23914", "CVE-2023-23915", "CVE-2023-23916");
  script_xref(name:"IAVA", value:"2023-A-0008-S");
  script_xref(name:"IAVA", value:"2023-A-0108-S");

  script_name(english:"FreeBSD : curl -- multiple vulnerabilities (be233fc6-bae7-11ed-a4fb-080027f5fec9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the be233fc6-bae7-11ed-a4fb-080027f5fec9 advisory.

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality fail when multiple URLs are requested serially. Using its HSTS support, curl can be
    instructed to use HTTPS instead of usingan insecure clear-text HTTP step even when HTTP is provided in the
    URL. ThisHSTS mechanism would however surprisingly be ignored by subsequent transferswhen done on the same
    command line because the state would not be properlycarried on. (CVE-2023-23914)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using its HSTS
    support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when
    HTTP is provided in the URL. This HSTS mechanism would however surprisingly fail when multiple transfers
    are done in parallel as the HSTS cache file gets overwritten by the most recentlycompleted transfer. A
    later HTTP-only transfer to the earlier host name would then *not* get upgraded properly to HSTS.
    (CVE-2023-23915)

  - An allocation of resources without limits or throttling vulnerability exists in curl <v7.88.0 based on the
    chained HTTP compression algorithms, meaning that a server response can be compressed multiple times and
    potentially with differentalgorithms. The number of acceptable links in this decompression chain
    wascapped, but the cap was implemented on a per-header basis allowing a maliciousserver to insert a
    virtually unlimited number of compression steps simply byusing many headers. The use of such a
    decompression chain could result in a malloc bomb, making curl end up spending enormous amounts of
    allocated heap memory, or trying to and returning out of memory errors. (CVE-2023-23916)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://curl.se/docs/security.html");
  # https://vuxml.freebsd.org/freebsd/be233fc6-bae7-11ed-a4fb-080027f5fec9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdf0f6cf");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23914");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'curl<7.88.0'
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
