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
  script_id(176906);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2022-4303",
    "CVE-2023-0286",
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-2650",
    "CVE-2023-24329"
  );
  script_xref(name:"IAVA", value:"2023-A-0283");
  script_xref(name:"IAVA", value:"2023-A-0118-S");

  script_name(english:"FreeBSD : Python -- multiple vulnerabilities (d86becfe-05a4-11ee-9d4a-080027eda32c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the d86becfe-05a4-11ee-9d4a-080027eda32c advisory.

  - The WP Limit Login Attempts WordPress plugin through 2.6.4 prioritizes getting a visitor's IP from certain
    HTTP headers over PHP's REMOTE_ADDR, which makes it possible to bypass IP-based restrictions on login
    forms. (CVE-2022-4303)

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

  - A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

  - Applications that use a non-default option when verifying certificates may be vulnerable to an attack from
    a malicious CA to circumvent certain checks. Invalid certificate policies in leaf certificates are
    silently ignored by OpenSSL and other certificate policy checks are skipped for that certificate. A
    malicious CA could use this to deliberately assert invalid certificate policies in order to circumvent
    policy checking on the certificate altogether. Policy processing is disabled by default but can be enabled
    by passing the `-policy' argument to the command line utilities or by calling the
    `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0465)

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

  - An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

  - Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be
    very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL
    subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to
    very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT
    IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit.
    OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the
    OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT
    IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER
    is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the
    translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n'
    being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic
    algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs
    in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be
    received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to
    specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest
    passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any
    version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In
    OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts
    anything that processes X.509 certificates, including simple things like verifying its signature. The
    impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's
    certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client
    authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509
    certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so
    these versions are considered not affected by this issue in such a way that it would be cause for concern,
    and the severity is therefore considered low. (CVE-2023-2650)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://pythoninsider.blogspot.com/2023/06/python-3114-31012-3917-3817-3717-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?614740b4");
  # https://vuxml.freebsd.org/freebsd/d86becfe-05a4-11ee-9d4a-080027eda32c.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e98c60");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24329");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python310");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python311");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:python39");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'python310<3.10.12',
    'python311<3.11.4',
    'python37<3.7.17',
    'python38<3.8.17',
    'python39<3.9.17'
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
