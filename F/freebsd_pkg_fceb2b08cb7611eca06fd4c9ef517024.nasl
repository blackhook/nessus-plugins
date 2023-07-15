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
  script_id(160481);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/04");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-1343",
    "CVE-2022-1434",
    "CVE-2022-1473"
  );
  script_xref(name:"IAVA", value:"2022-A-0186-S");

  script_name(english:"FreeBSD : OpenSSL -- Multiple vulnerabilities (fceb2b08-cb76-11ec-a06f-d4c9ef517024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the fceb2b08-cb76-11ec-a06f-d4c9ef517024 advisory.

  - The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This
    script is distributed by some operating systems in a manner where it is automatically executed. On such
    operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of
    the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool.
    Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n).
    Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd). (CVE-2022-1292)

  - The function `OCSP_basic_verify` verifies the signer certificate on an OCSP response. In the case where
    the (non-default) flag OCSP_NOCHECKS is used then the response will be positive (meaning a successful
    verification) even in the case where the response signing certificate fails to verify. It is anticipated
    that most users of `OCSP_basic_verify` will not use the OCSP_NOCHECKS flag. In this case the
    `OCSP_basic_verify` function will return a negative value (indicating a fatal error) in the case of a
    certificate verification failure. The normal expected return value in this case would be 0. This issue
    also impacts the command line OpenSSL ocsp application. When verifying an ocsp response with the
    -no_cert_checks option the command line application will report that the verification is successful even
    though it has in fact failed. In this case the incorrect successful response will also be accompanied by
    error messages showing the failure and contradicting the apparently successful result. Fixed in OpenSSL
    3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1343)

  - The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses the AAD data as the MAC key.
    This makes the MAC key trivially predictable. An attacker could exploit this issue by performing a man-in-
    the-middle attack to modify data being sent from one endpoint to an OpenSSL 3.0 recipient such that the
    modified data would still pass the MAC integrity check. Note that data sent from an OpenSSL 3.0 endpoint
    to a non-OpenSSL 3.0 endpoint will always be rejected by the recipient and the connection will fail at
    that point. Many application protocols require data to be sent from the client to the server first.
    Therefore, in such a case, only an OpenSSL 3.0 server would be impacted when talking to a non-OpenSSL 3.0
    client. If both endpoints are OpenSSL 3.0 then the attacker could modify data being sent in both
    directions. In this case both clients and servers could be affected, regardless of the application
    protocol. Note that in the absence of an attacker this bug means that an OpenSSL 3.0 endpoint
    communicating with a non-OpenSSL 3.0 endpoint will fail to complete the handshake when using this
    ciphersuite. The confidentiality of data is not impacted by this issue, i.e. an attacker cannot decrypt
    data that has been encrypted using this ciphersuite - they can only modify it. In order for this attack to
    work both endpoints must legitimately negotiate the RC4-MD5 ciphersuite. This ciphersuite is not compiled
    by default in OpenSSL 3.0, and is not available within the default provider or the default ciphersuite
    list. This ciphersuite will never be used if TLSv1.3 has been negotiated. In order for an OpenSSL 3.0
    endpoint to use this ciphersuite the following must have occurred: 1) OpenSSL must have been compiled with
    the (non-default) compile time option enable-weak-ssl-ciphers 2) OpenSSL must have had the legacy provider
    explicitly loaded (either through application code or via configuration) 3) The ciphersuite must have been
    explicitly added to the ciphersuite list 4) The libssl security level must have been set to 0 (default is
    1) 5) A version of SSL/TLS below TLSv1.3 must have been negotiated 6) Both endpoints must negotiate the
    RC4-MD5 ciphersuite in preference to any others that both endpoints have in common Fixed in OpenSSL 3.0.3
    (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1434)

  - The OPENSSL_LH_flush() function, which empties a hash table, contains a bug that breaks reuse of the
    memory occuppied by the removed hash table entries. This function is used when decoding certificates or
    keys. If a long lived process periodically decodes certificates or keys its memory usage will expand
    without bounds and the process might be terminated by the operating system causing a denial of service.
    Also traversing the empty hash table entries will take increasingly more time. Typically such long lived
    processes might be TLS clients or TLS servers configured to accept client certificate authentication. The
    function was added in the OpenSSL 3.0 version thus older releases are not affected by the issue. Fixed in
    OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). (CVE-2022-1473)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20220503.txt");
  # https://vuxml.freebsd.org/freebsd/fceb2b08-cb76-11ec-a06f-d4c9ef517024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afa0c74a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl-devel");
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
    'openssl-devel<3.0.3',
    'openssl<1.1.1o,1'
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
