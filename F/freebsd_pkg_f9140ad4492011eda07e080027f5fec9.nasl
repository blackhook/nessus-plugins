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
  script_id(166005);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id(
    "CVE-2022-2031",
    "CVE-2022-32742",
    "CVE-2022-32744",
    "CVE-2022-32745",
    "CVE-2022-32746"
  );
  script_xref(name:"IAVA", value:"2022-A-0299-S");

  script_name(english:"FreeBSD : samba -- Multiple vulnerabilities (f9140ad4-4920-11ed-a07e-080027f5fec9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the f9140ad4-4920-11ed-a07e-080027f5fec9 advisory.

  - A flaw was found in Samba. The security vulnerability occurs when KDC and the kpasswd service share a
    single account and set of keys, allowing them to decrypt each other's tickets. A user who has been
    requested to change their password, can exploit this flaw to obtain and use tickets to other services.
    (CVE-2022-2031)

  - A flaw was found in Samba. Some SMB1 write requests were not correctly range-checked to ensure the client
    had sent enough data to fulfill the write, allowing server memory contents to be written into the file (or
    printer) instead of client-supplied data. The client cannot control the area of the server memory written
    to the file (or printer). (CVE-2022-32742)

  - A flaw was found in Samba. The KDC accepts kpasswd requests encrypted with any key known to it. By
    encrypting forged kpasswd requests with its own key, a user can change other users' passwords, enabling
    full domain takeover. (CVE-2022-32744)

  - A flaw was found in Samba. Samba AD users can cause the server to access uninitialized data with an LDAP
    add or modify the request, usually resulting in a segmentation fault. (CVE-2022-32745)

  - A flaw was found in the Samba AD LDAP server. The AD DC database audit logging module can access LDAP
    message values freed by a preceding database module, resulting in a use-after-free issue. This issue is
    only possible when modifying certain privileged attributes, such as userAccountControl. (CVE-2022-32746)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.samba.org/archive/samba-announce/2022/000609.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-2031.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-32742.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-32744.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-32745.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-32746.html");
  # https://vuxml.freebsd.org/freebsd/f9140ad4-4920-11ed-a07e-080027f5fec9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0bfe53a8");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba412");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba413");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'samba412<4.12.16',
    'samba413<4.13.17_2'
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
