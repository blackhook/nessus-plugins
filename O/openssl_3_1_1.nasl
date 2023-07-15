#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173267);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id(
    "CVE-2023-0464",
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466"
  );
  script_xref(name:"IAVA", value:"2023-A-0158");

  script_name(english:"OpenSSL 3.1.0 < 3.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.1.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the 3.1.1 advisory.

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=facfb1ab745646e97a1920977ae4a9965ea61d5c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e262388e");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0465");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230328.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/secpolicy.html");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=fc814a30fc4f0bc54fcea7d9a7462f5457aab061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b1e6e3d");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0466");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2017771e2db3e2b96f89bbe8766c3209f6a99545
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53676b5b");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-0464");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230322.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("openssl/port", "installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '3.1.0', 'fixed_version' : '3.1.1'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
