#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
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
  script_id(100140);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7478", "CVE-2017-7479");

  script_name(english:"FreeBSD : OpenVPN -- two remote denial-of-service vulnerabilities (04cc7bd2-3686-11e7-aa64-080027ef73ec)");
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
"Samuli Seppanen reports :

OpenVPN v2.4.0 was audited for security vulnerabilities independently
by Quarkslabs (funded by OSTIF) and Cryptography Engineering (funded
by Private Internet Access) between December 2016 and April 2017. The
primary findings were two remote denial-of-service vulnerabilities.
Fixes to them have been backported to v2.3.15.

An authenticated client can do the 'three way handshake'
(P_HARD_RESET, P_HARD_RESET, P_CONTROL), where the P_CONTROL packet is
the first that is allowed to carry payload. If that payload is too
big, the OpenVPN server process will stop running due to an ASSERT()
exception. That is also the reason why servers using
tls-auth/tls-crypt are protected against this attack - the P_CONTROL
packet is only accepted if it contains the session ID we specified,
with a valid HMAC (challenge-response). (CVE-2017-7478)

An authenticated client can cause the server's the packet-id counter
to roll over, which would lead the server process to hit an ASSERT()
and stop running. To make the server hit the ASSERT(), the client must
first cause the server to send it 2^32 packets (at least 196 GB)."
  );
  # https://openvpn.net/index.php/open-source/downloads.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://openvpn.net/community-downloads/"
  );
  # https://community.openvpn.net/openvpn/wiki/QuarkslabAndCryptographyEngineerAudits
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c722f7c"
  );
  # https://ostif.org/?p=870&preview=true
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ade83fb"
  );
  # https://www.privateinternetaccess.com/blog/2017/05/openvpn-2-4-2-fixes-critical-issues-discovered-openvpn-audit-reports/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07d71b0e"
  );
  # https://vuxml.freebsd.org/freebsd/04cc7bd2-3686-11e7-aa64-080027ef73ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bf3927c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openvpn-mbedtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openvpn-polarssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openvpn23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openvpn23-polarssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"openvpn<2.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openvpn>=2.4.0<2.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openvpn23<2.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openvpn-mbedtls>=2.4.0<2.4.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openvpn-polarssl<2.3.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openvpn23-polarssl<2.3.15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
