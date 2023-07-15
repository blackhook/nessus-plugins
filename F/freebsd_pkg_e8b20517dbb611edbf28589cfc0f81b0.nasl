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
  script_id(174391);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2023-25824");

  script_name(english:"FreeBSD : mod_gnutls -- Infinite Loop on request read timeout (e8b20517-dbb6-11ed-bf28-589cfc0f81b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the e8b20517-dbb6-11ed-bf28-589cfc0f81b0 advisory.

  - Mod_gnutls is a TLS module for Apache HTTPD based on GnuTLS. Versions from 0.9.0 to 0.12.0 (including) did
    not properly fail blocking read operations on TLS connections when the transport hit timeouts. Instead it
    entered an endless loop retrying the read operation, consuming CPU resources. This could be exploited for
    denial of service attacks. If trace level logging was enabled, it would also produce an excessive amount
    of log output during the loop, consuming disk space. The problem has been fixed in commit
    d7eec4e598158ab6a98bf505354e84352f9715ec, please update to version 0.12.1. There are no workarounds, users
    who cannot update should apply the errno fix detailed in the security advisory. (CVE-2023-25824)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://mod.gnutls.org/browser/mod_gnutls/CHANGELOG?rev=17b2836dc3e27754159ffb098323a4cd4426192f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f203d6eb");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-25824");
  # https://vuxml.freebsd.org/freebsd/e8b20517-dbb6-11ed-bf28-589cfc0f81b0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b72d9b0d");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25824");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ap24-mod_gnutls");
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
    'ap24-mod_gnutls<0.12.1'
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
