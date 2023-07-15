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
  script_id(165686);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-2879", "CVE-2022-2880", "CVE-2022-41715");
  script_xref(name:"IAVB", value:"2022-B-0042-S");

  script_name(english:"FreeBSD : go -- multiple vulnerabilities (854c2afb-4424-11ed-af97-adcabf310f9b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 854c2afb-4424-11ed-af97-adcabf310f9b advisory.

  - The Go project reports: archive/tar: unbounded memory consumption when reading             headers
    Reader.Read did not set a limit on the maximum size of             file headers. A maliciously crafted
    archive could cause             Read to allocate unbounded amounts of memory, potentially
    causing resource exhaustion or panics. Reader.Read now             limits the maximum size of header
    blocks to 1 MiB. net/http/httputil: ReverseProxy should not forward             unparseable query
    parameters Requests forwarded by ReverseProxy included the raw             query parameters from the
    inbound request, including             unparseable parameters rejected by net/http. This could
    permit query parameter smuggling when a Go proxy             forwards a parameter with an unparseable
    value. ReverseProxy will now sanitize the query parameters in             the forwarded query when the
    outbound request's Form             field is set after the ReverseProxy.Director function
    returns, indicating that the proxy has parsed the query             parameters. Proxies which do not parse
    query parameters             continue to forward the original query parameters             unchanged.
    regexp/syntax: limit memory used by parsing regexps The parsed regexp representation is linear in the size
    of the input, but in some cases the constant factor can be             as high as 40,000, making
    relatively small regexps consume             much larger amounts of memory. Each regexp being parsed is
    now limited to a 256 MB             memory footprint. Regular expressions whose             representation
    would use more space than that are now             rejected. Normal use of regular expressions is
    unaffected. (CVE-2022-2879, CVE-2022-2880, CVE-2022-41715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://groups.google.com/g/golang-announce/c/xtuG5faxtaU/m/jEhlI_5WBgAJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18c575a0");
  # https://vuxml.freebsd.org/freebsd/854c2afb-4424-11ed-af97-adcabf310f9b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?decfd70f");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2880");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go118");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go119");
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
    'go118<1.18.7',
    'go119<1.19.2'
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
