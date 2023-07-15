#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156100);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2021-4044", "CVE-2021-4160");
  script_xref(name:"IAVA", value:"2021-A-0602-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.1 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.1. It is, therefore, affected by a vulnerability as
referenced in the 3.0.1 advisory.

  - Internally libssl in OpenSSL calls X509_verify_cert() on the client side to verify a certificate supplied
    by a server. That function may return a negative return value to indicate an internal error (for example
    out of memory). Such a negative return value is mishandled by OpenSSL and will cause an IO function (such
    as SSL_connect() or SSL_do_handshake()) to not indicate success and a subsequent call to SSL_get_error()
    to return the value SSL_ERROR_WANT_RETRY_VERIFY. This return value is only supposed to be returned by
    OpenSSL if the application has previously called SSL_CTX_set_cert_verify_callback(). Since most
    applications do not do this the SSL_ERROR_WANT_RETRY_VERIFY return value from SSL_get_error() will be
    totally unexpected and applications may not behave correctly as a result. The exact behaviour will depend
    on the application but it could result in crashes, infinite loops or other similar incorrect responses.
    This issue is made more serious in combination with a separate bug in OpenSSL 3.0 that will cause
    X509_verify_cert() to indicate an internal error when processing a certificate chain. This will occur
    where a certificate does not include the Subject Alternative Name extension but where a Certificate
    Authority has enforced name constraints. This issue can occur even with valid chains. By combining the two
    issues an attacker could induce incorrect, application dependent behaviour. Fixed in OpenSSL 3.0.1
    (Affected 3.0.0). (CVE-2021-4044)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/758754966791c537ea95241438454aa86f91f256
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7b84fa5");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20211214.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("openssl/port", "installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.0.0', 'fixed_version' : '3.0.1'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
