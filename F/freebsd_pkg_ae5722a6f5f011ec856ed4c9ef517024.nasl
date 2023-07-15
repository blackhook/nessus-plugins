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
  script_id(162550);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208"
  );
  script_xref(name:"IAVA", value:"2022-A-0255-S");

  script_name(english:"FreeBSD : cURL -- Multiple vulnerabilities (ae5722a6-f5f0-11ec-856e-d4c9ef517024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the ae5722a6-f5f0-11ec-856e-d4c9ef517024 advisory.

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - A malicious server can serve excessive amounts of `Set-Cookie:` headers in a HTTP response to curl and
    curl < 7.84.0 stores all of them. A sufficiently large amount of (big) cookies make subsequent HTTP
    requests to this, or other servers to which the cookies match, create requests that become larger than the
    threshold that curl uses internally to avoid sending crazy large requests (1048576 bytes) and instead
    returns an error.This denial state might remain for as long as the same cookies are kept, match and
    haven't expired. Due to cookie matching rules, a server on `foo.example.com` can set cookies that also
    would match for `bar.example.com`, making it it possible for a sister server to effectively cause a
    denial of service for a sibling site on the same second level domain using this method. (CVE-2022-32205)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://curl.se/docs/security.html");
  # https://vuxml.freebsd.org/freebsd/ae5722a6-f5f0-11ec-856e-d4c9ef517024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90626522");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'curl>=7.16.4<7.84.0'
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
