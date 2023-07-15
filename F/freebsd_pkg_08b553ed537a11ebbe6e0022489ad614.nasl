#
# (C) Tenable Network Security, Inc.
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
  script_id(145024);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-1971", "CVE-2020-8265", "CVE-2020-8287");
  script_xref(name:"IAVB", value:"2021-B-0004-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"FreeBSD : Node.js -- January 2021 Security Releases (08b553ed-537a-11eb-be6e-0022489ad614)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Node.js reports : use-after-free in TLSWrap (High) (CVE-2020-8265)
Affected Node.js versions are vulnerable to a use-after-free bug in
its TLS implementation. When writing to a TLS enabled socket,
node::StreamBase::Write calls node::TLSWrap::DoWrite with a freshly
allocated WriteWrap object as first argument. If the DoWrite method
does not return an error, this object is passed back to the caller as
part of a StreamWriteResult structure. This may be exploited to
corrupt memory leading to a Denial of Service or potentially other
exploits. HTTP Request Smuggling in nodejs (Low) (CVE-2020-8287)
Affected versions of Node.js allow two copies of a header field in a
http request. For example, two Transfer-Encoding header fields. In
this case Node.js identifies the first header field and ignores the
second. This can lead to HTTP Request Smuggling. OpenSSL -
EDIPARTYNAME NULL pointer de-reference (CVE-2020-1971) iThis is a
vulnerability in OpenSSL which may be exploited through Node.js. You
can read more about it in
https://www.openssl.org/news/secadv/20201208.txt.");
  # https://nodejs.org/en/blog/vulnerability/january-2021-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59c0b90");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20201208.txt");
  # https://vuxml.freebsd.org/freebsd/08b553ed-537a-11eb-be6e-0022489ad614.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c99c220e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (pkg_test(save_report:TRUE, pkg:"node10<10.23.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node12<12.20.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node14<14.15.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<15.5.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
