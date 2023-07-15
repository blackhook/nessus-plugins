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
  script_id(140627);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-8201", "CVE-2020-8251", "CVE-2020-8252");
  script_xref(name:"IAVB", value:"2020-B-0057-S");

  script_name(english:"FreeBSD : Node.js -- September 2020 Security Releases (4ca5894c-f7f1-11ea-8ff8-0022489ad614)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Node.js reports :

Updates are now available for v10,x, v12.x and v14.x Node.js release
lines for the following issues. HTTP Request Smuggling due to
CR-to-Hyphen conversion (High) (CVE-2020-8201) Affected Node.js
versions converted carriage returns in HTTP request headers to a
hyphen before parsing. This can lead to HTTP Request Smuggling as it
is a non-standard interpretation of the header.

Impacts :

- All versions of the 14.x and 12.x releases line Denial of Service by
resource exhaustion CWE-400 due to unfinished HTTP/1.1 requests
(Critical) (CVE-2020-8251) Node.js is vulnerable to HTTP denial of
service (DOS) attacks based on delayed requests submission which can
make the server unable to accept new connections. The fix a new
http.Server option called requestTimeout with a default value of 0
which means it is disabled by default. This should be set when Node.js
is used as an edge server, for more details refer to the
documentation.

Impacts :

- All versions of the 14.x release line fs.realpath.native on may
cause buffer overflow (Medium) (CVE-2020-8252) libuv's realpath
implementation incorrectly determined the buffer size which can result
in a buffer overflow if the resolved path is longer than 256 bytes.

Impacts :

- All versions of the 10.x release line

- All versions of the 12.x release line

- All versions of the 14.x release line before 14.9.0");
  # https://nodejs.org/en/blog/vulnerability/september-2020-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64b99430");
  # https://vuxml.freebsd.org/freebsd/4ca5894c-f7f1-11ea-8ff8-0022489ad614.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39cb0a14");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8201");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (pkg_test(save_report:TRUE, pkg:"node<14.11.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node12<12.18.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node10<10.22.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
