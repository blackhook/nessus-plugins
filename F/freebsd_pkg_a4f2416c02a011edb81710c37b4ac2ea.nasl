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
  script_id(163105);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1962",
    "CVE-2022-28131",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148"
  );
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"FreeBSD : go -- multiple vulnerabilities (a4f2416c-02a0-11ed-b817-10c37b4ac2ea)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the a4f2416c-02a0-11ed-b817-10c37b4ac2ea advisory.

  - The Go project reports: net/http: improper sanitization of Transfer-Encoding             header The HTTP/1
    client accepted some invalid             Transfer-Encoding headers as indicating a chunked
    encoding. This could potentially allow for request             smuggling, but only if combined with an
    intermediate             server that also improperly failed to reject the header             as invalid.
    When httputil.ReverseProxy.ServeHTTP was called with a             Request.Header map containing a nil
    value for the             X-Forwarded-For header, ReverseProxy would set the client             IP as the
    value of the X-Forwarded-For header, contrary to             its documentation. In the more usual case
    where a Director             function set the X-Forwarded-For header value to nil,
    ReverseProxy would leave the header unmodified as             expected. compress/gzip: stack exhaustion in
    Reader.Read Calling Reader.Read on an archive containing a large             number of concatenated
    0-length compressed files can             cause a panic due to stack exhaustion. encoding/xml: stack
    exhaustion in Unmarshal Calling Unmarshal on a XML document into a Go struct             which has a
    nested field that uses the any field tag can             cause a panic due to stack exhaustion.
    encoding/xml: stack exhaustion in Decoder.Skip Calling Decoder.Skip when parsing a deeply nested XML
    document can cause a panic due to stack exhaustion. encoding/gob: stack exhaustion in Decoder.Decode
    Calling Decoder.Decode on a message which contains             deeply nested structures can cause a panic
    due to stack             exhaustion. path/filepath: stack exhaustion in Glob Calling Glob on a path which
    contains a large number of             path separators can cause a panic due to stack
    exhaustion. io/fs: stack exhaustion in Glob Calling Glob on a path which contains a large number of
    path separators can cause a panic due to stack             exhaustion. go/parser: stack exhaustion in all
    Parse* functions Calling any of the Parse functions on Go source code             which contains deeply
    nested types or declarations can             cause a panic due to stack exhaustion. (CVE-2022-1705,
    CVE-2022-1962, CVE-2022-28131, CVE-2022-30630, CVE-2022-30631, CVE-2022-30632, CVE-2022-30633,
    CVE-2022-30635, CVE-2022-32148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-dev/c/frczlF8OFQ0");
  # https://vuxml.freebsd.org/freebsd/a4f2416c-02a0-11ed-b817-10c37b4ac2ea.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27a1175e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go117");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go118");
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
    'go117<1.17.12',
    'go118<1.18.4'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
