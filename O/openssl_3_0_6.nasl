#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166047);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2022-3358");
  script_xref(name:"IAVA", value:"2022-A-0415-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.6 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.6. It is, therefore, affected by a vulnerability as
referenced in the 3.0.6 advisory.

  - OpenSSL supports creating a custom cipher via the legacy EVP_CIPHER_meth_new() function and associated
    function calls. This function was deprecated in OpenSSL 3.0 and application authors are instead encouraged
    to use the new provider mechanism in order to implement custom ciphers. OpenSSL versions 3.0.0 to 3.0.5
    incorrectly handle legacy custom ciphers passed to the EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() and
    EVP_CipherInit_ex2() functions (as well as other similarly named encryption and decryption initialisation
    functions). Instead of using the custom cipher directly it incorrectly tries to fetch an equivalent cipher
    from the available providers. An equivalent cipher is found based on the NID passed to
    EVP_CIPHER_meth_new(). This NID is supposed to represent the unique NID for a given cipher. However it is
    possible for an application to incorrectly pass NID_undef as this value in the call to
    EVP_CIPHER_meth_new(). When NID_undef is used in this way the OpenSSL encryption/decryption initialisation
    function will match the NULL cipher as being equivalent and will fetch this from the available providers.
    This will succeed if the default provider has been loaded (or if a third party provider has been loaded
    that offers this cipher). Using the NULL cipher means that the plaintext is emitted as the ciphertext.
    Applications are only affected by this issue if they call EVP_CIPHER_meth_new() using NID_undef and
    subsequently use it in a call to an encryption/decryption initialisation function. Applications that only
    use SSL/TLS are not impacted by this issue. Fixed in OpenSSL 3.0.6 (Affected 3.0.0-3.0.5). (CVE-2022-3358)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cve.org/CVERecord?id=CVE-2022-3358");
  # https://github.com/openssl/openssl/commit/5485c56679d7c49b96e8fc8ca708b0b7e7c03c4b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8748528d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20221011.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("openssl/port", "installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.0.0', 'fixed_version' : '3.0.6'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
