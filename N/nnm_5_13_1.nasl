#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149403);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-1971",
    "CVE-2021-3449",
    "CVE-2021-3450",
    "CVE-2021-23840",
    "CVE-2021-23841"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Nessus Network Monitor < 5.13.1 Multiple Vulnerabilities (TNS-2021-09)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Network Monitor (NNM) installed on the remote host is prior to 5.13.1. It is, therefore, affected
by multiple vulnerabilities:

  - The X.509 GeneralName type is a generic type for representing different types of names. One of those 
    name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different
    instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both 
    GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a 
    possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 
    1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded 
    in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp 
    authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an 
    attacker can control both items being compared then that attacker could trigger a crash. For example if
    the attacker can trick a client or server into checking a malicious certificate against a malicious CRL 
    then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a
    certificate. This checking happens prior to the signatures on the certificate and CRL being verified. 
    OpenSSL's s_server, s_client and verify tools have support for the -crl_download option which implements 
    automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that 
    an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of 
    EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will 
    accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. 
    Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i 
    (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w). (CVE-2020-1971)
  
  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value
    based on the issuer and serial number data contained within an X509 certificate. However it fails to 
    correctly handle any errors that may occur while parsing the issuer field (which might occur if the 
    issuer field is maliciously constructed). This may subsequently result in a NULL pointer deref and a 
    crash leading to a potential denial of service attack. The function X509_issuer_and_serial_hash() is 
    never directly called by OpenSSL itself so applications are only vulnerable if they use this function 
    directly and they use it on certificates that may have been obtained from untrusted sources. OpenSSL 
    versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to OpenSSL 
    1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out of 
    support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade
    to 1.0.2y. Other users should upgrade to 1.1.1j. (CVE-2021-23841)

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length 
    argument in some cases where the input length is close to the maximum permissable length for an integer
    on the platform. In such cases the return value from the function call will be 1 (indicating success), 
    but the output length value will be negative. This could cause applications to behave incorrectly or 
    crash. OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should 
    upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL
    1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 
    1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. (CVE-2021-23840)
  
  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-09");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor version 5.13.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '5.13.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

