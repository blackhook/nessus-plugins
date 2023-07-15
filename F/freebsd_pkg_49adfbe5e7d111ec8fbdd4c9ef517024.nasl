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
  script_id(161984);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id(
    "CVE-2022-26377",
    "CVE-2022-28330",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-29404",
    "CVE-2022-30522",
    "CVE-2022-30556",
    "CVE-2022-31813"
  );
  script_xref(name:"IAVA", value:"2022-A-0230-S");

  script_name(english:"FreeBSD : Apache httpd -- Multiple vulnerabilities (49adfbe5-e7d1-11ec-8fbd-d4c9ef517024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 49adfbe5-e7d1-11ec-8fbd-d4c9ef517024 advisory.

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
    (CVE-2022-26377)

  - Apache HTTP Server 2.4.53 and earlier on Windows may read beyond bounds when configured to process
    requests with the mod_isapi module. (CVE-2022-28330)

  - The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an
    attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as with
    mod_luas r:puts() function. (CVE-2022-28614)

  - Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in
    ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the
    server can be coerced into such a call, third-party modules or lua scripts that use ap_strcmp_match() may
    hypothetically be affected. (CVE-2022-28615)

  - In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0)
    may cause a denial of service due to no default limit on possible input size. (CVE-2022-29404)

  - If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in contexts where the input
    to mod_sed may be very large, mod_sed may make excessively large memory allocations and trigger an abort.
    (CVE-2022-30522)

  - Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point
    past the end of the storage allocated for the buffer. (CVE-2022-30556)

  - Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on
    client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on
    the origin server/application. (CVE-2022-31813)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.apache.org/httpd/CHANGES_2.4.54");
  # https://vuxml.freebsd.org/freebsd/49adfbe5-e7d1-11ec-8fbd-d4c9ef517024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4de244ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'apache24<2.4.54'
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
