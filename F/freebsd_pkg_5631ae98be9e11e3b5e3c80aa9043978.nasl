#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(73389);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/05");

  script_cve_id("CVE-2014-0160");
  script_xref(name:"FreeBSD", value:"FreeBSD-SA-14:06.openssl");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"FreeBSD : OpenSSL -- Remote Information Disclosure (5631ae98-be9e-11e3-b5e3-c80aa9043978)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"OpenSSL Reports :

A missing bounds check in the handling of the TLS heartbeat extension
can be used to reveal up to 64k of memory to a connected client or
server.

Affected users should upgrade to OpenSSL 1.0.1g. Users unable to
immediately upgrade can alternatively recompile OpenSSL with
-DOPENSSL_NO_HEARTBEATS.

The bug allows anyone on the Internet to read the memory of the
systems protected by the vulnerable versions of the OpenSSL software.
This compromises the secret keys used to identify the service
providers and to encrypt the traffic, the names and passwords of the
users and the actual content. This allows attackers to eavesdrop
communications, steal data directly from the services and users and to
impersonate services and users.

The code used to handle the Heartbeat Extension does not do sufficient
boundary checks on record length, which allows reading beyond the
actual payload.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv_20140407.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0076");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  # http://www.freebsd.org/ports/portaudit/5631ae98-be9e-11e3-b5e3-c80aa9043978.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccfdc540");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mingw32-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

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

if (pkg_test(save_report:TRUE, pkg:"openssl>=1.0.1<1.0.1_10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mingw32-openssl>=1.0.1<1.0.1g")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
