#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160640);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-3711", "CVE-2021-3712");

  script_name(english:"Nessus Network Monitor < 6.0.0 Multiple Vulnerabilities (TNS-2022-02)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Network Monitor (NNM) installed on the remote host is prior to 6.0.0. It is, therefore, affected
by multiple vulnerabilities:

  - ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a buffer 
    holding the string data and a field holding the buffer length. This contrasts with normal C strings which 
    are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not a strict 
    requirement, ASN.1 strings that are parsed using OpenSSL's own d2i functions (and other similar parsing 
    functions) as well as any string whose value has been set with the ASN1_STRING_set() function will additionally 
    NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for applications to directly 
    construct valid ASN1_STRING structures which do not NUL terminate the byte array by directly setting the data 
    and length fields in the ASN1_STRING array. This can also happen by using the ASN1_STRING_set0() function. 
    Numerous OpenSSL functions that print ASN.1 data have been found to assume that the ASN1_STRING byte array 
    will be NUL terminated, even though this is not guaranteed for strings that have been directly constructed. 
    Where an application requests an ASN.1 structure to be printed, and where that ASN.1 structure contains 
    ASN1_STRINGs that have been directly constructed by the application without NUL terminating the data field, 
    then a read buffer overrun can occur. The same thing can also occur during name constraints processing of 
    certificates (for example if a certificate has been directly constructed by the application instead of 
    loading it via the OpenSSL parsing functions, and the certificate contains non NUL terminated ASN1_STRING
     structures). It can also occur in the X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() 
     functions. If a malicious actor can cause an application to directly construct an ASN1_STRING and then 
     process it through one of the affected OpenSSL functions then this issue could be hit. This might result 
     in a crash (causing a Denial of Service attack). It could also result in the disclosure of private memory 
     contents (such as private keys, or sensitive plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). 
     Fixed in OpenSSL 1.0.2za (Affected 1.0.2-1.0.2y).
  
  - In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). 
    Typically an application will call this function twice. The first time, on entry, the out parameter can be 
    NULL and, on exit, the outlen parameter is populated with the buffer size required to hold the decrypted 
    plaintext. The application can then allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again, 
    but this time passing a non-NULL value for the out parameter. A bug in the implementation of the SM2 
    decryption code means that the calculation of the buffer size required to hold the plaintext returned by the
     first call to EVP_PKEY_decrypt() can be smaller than the actual size required by the second call. This can 
     lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a second time with a buffer 
     that is too small. A malicious attacker who is able present SM2 content for decryption to an application 
     could cause attacker chosen data to overflow the buffer by up to a maximum of 62 bytes altering the contents 
     of other data held after the buffer, possibly changing application behaviour or causing the application to 
     crash. The location of the buffer is application dependent but is typically heap allocated. Fixed in 
     OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor version 6.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version': '5.13.1', 'fixed_version' : '6.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

