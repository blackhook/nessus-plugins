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

include("compat.inc");

if (description)
{
  script_id(140678);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2019-18348", "CVE-2019-20907", "CVE-2020-14422", "CVE-2020-15523", "CVE-2020-8492");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"FreeBSD : Python -- multiple vulnerabilities (2cb21232-fb32-11ea-a929-a4bf014bf5f7)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Python reports :

bpo-39603: Prevent http header injection by rejecting control
characters in http.client.putrequest(...).

bpo-29778: Ensure python3.dll is loaded from correct locations when
Python is embedded (CVE-2020-15523).

bpo-41004: CVE-2020-14422: The __hash__() methods of
ipaddress.IPv4Interface and ipaddress.IPv6Interface incorrectly
generated constant hash values of 32 and 128 respectively. This
resulted in always causing hash collisions. The fix uses hash() to
generate hash values for the tuple of (address, mask length, network
address).

bpo-39073: Disallow CR or LF in email.headerregistry.Address arguments
to guard against header injection attacks.

bpo-38576: Disallow control characters in hostnames in http.client,
addressing CVE-2019-18348. Such potentially malicious header injection
URLs now cause a InvalidURL to be raised.

bpo-39503: CVE-2020-8492: The AbstractBasicAuthHandler class of the
urllib.request module uses an inefficient regular expression which can
be exploited by an attacker to cause a denial of service. Fix the
regex to prevent the catastrophic backtracking. Vulnerability reported
by Ben Caller and Matt Schwager.

bpo-38945: Newline characters have been escaped when performing uu
encoding to prevent them from overflowing into to content section of
the encoded file. This prevents malicious or accidental modification
of data during the decoding process.

bpo-38804: Fixes a ReDoS vulnerability in http.cookiejar. Patch by Ben
Caller.

bpo-39017: Avoid infinite loop when reading specially crafted TAR
files using the tarfile module (CVE-2019-20907).

bpo-41183: Use 3072 RSA keys and SHA-256 signature for test certs and
keys.

bpo-39503: AbstractBasicAuthHandler of urllib.request now parses all
WWW-Authenticate HTTP headers and accepts multiple challenges per
header: use the realm of the first Basic challenge."
  );
  # https://vuxml.freebsd.org/freebsd/2cb21232-fb32-11ea-a929-a4bf014bf5f7.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5609d352"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15523");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python35");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"python35<3.5.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
