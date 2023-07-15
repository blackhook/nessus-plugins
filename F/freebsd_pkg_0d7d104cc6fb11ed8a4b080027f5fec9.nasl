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
  script_id(173330);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/01");

  script_cve_id(
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538"
  );
  script_xref(name:"IAVA", value:"2023-A-0153-S");

  script_name(english:"FreeBSD : curl -- multiple vulnerabilities (0d7d104c-c6fb-11ed-8a4b-080027f5fec9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0d7d104c-c6fb-11ed-8a4b-080027f5fec9 advisory.

  - The vulnerability exists due to missing documentation of the TELNET protocol support and the ability to
    pass on user name and telnet options for the server negotiation. A remote attacker can manipulate the
    connection sending unexpected data to the server via the affected client. (CVE-2023-27533)

  - The vulnerability exists due to insufficient validation of user-supplied input in the SFTP support when
    handling the tilde ~ character in the filepath. cURL will replace the tilde character to the current
    user's home directory and can reveal otherwise restricted files. (CVE-2023-27534)

  - The vulnerability exists due to cURL will reuse a previously created FTP connection even when one or more
    options had been changed that could have made the effective user a very different one. A remote attacker
    can connect to the FTP server using credentials supplied by another user and gain access to otherwise
    restricted functionality. (CVE-2023-27535)

  - The vulnerability exists due to cURL will reuse a previously created connection even when the GSS
    delegation (CURLOPT_GSSAPI_DELEGATION) option had been changed that could have changed the user's
    permissions in a second transfer. libcurl keeps previously used connections in a connection pool for
    subsequent transfers to reuse if one of them matches the setup. However, this GSS delegation setting was
    left out from the configuration match checks, making them match too easily, affecting
    krb5/kerberos/negotiate/GSSAPI transfers. (CVE-2023-27536)

  - The vulnerability exists due to a boundary error when sharing HSTS data between connection. A remote
    attacker can initiate HSTS connection, trigger a double free error and execute arbitrary code on the
    target system. (CVE-2023-27537)

  - The vulnerability exists due to the way libcurl handles previously used connections in a connection pool
    for subsequent transfers. Several SSH settings were left out from the configuration match checks,
    resulting in erroneous matches for different resources. As a result, libcurl can send authentication
    string from one resource to another, exposing credentials to a third-party. (CVE-2023-27538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://curl.se/docs/security.html");
  # https://vuxml.freebsd.org/freebsd/0d7d104c-c6fb-11ed-8a4b-080027f5fec9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1e5f407");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-27534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/23");

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
    'curl<8.0.0'
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
