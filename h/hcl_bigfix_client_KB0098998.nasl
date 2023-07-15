#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168825);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2022-22576",
    "CVE-2022-27544",
    "CVE-2022-27545",
    "CVE-2022-27775",
    "CVE-2022-27776"
  );
  script_xref(name:"IAVA", value:"2022-A-0514");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"HCL BigFix Multiple Vulnerabilities (KB0098998)");

  script_set_attribute(attribute:"synopsis", value:
"HCL BigFix is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HCL BigFix Client installed on the remote host is affected by multiple vulnerabilities, including the
following:

  - An improper authentication vulnerability exists in the curl subcomponent which might allow reuse
    OAUTH2-authenticated connections without properly making sure that the connection was authenticated with
    the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S), IMAP(S),
    POP3(S) and LDAP(S) (openldap only). (CVE-2022-22576)

  - An information disclosure vulnerability exists in the curl subcomponent. Using an IPv6 address that was in
    the connection pool but with a different zone id it could reuse a connection instead. (CVE-2022-27775)

  - A insufficiently protected credentials vulnerability in fixed the curl subcomponent might leak
    authentication or cookie header data on HTTP redirects to the same host but another port number.
    (CVE-2022-27776)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0098998
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1447ec9c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HCL BigFix Platform version 9.5.20, 10.0.7, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hcltech:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tivoli_endpoint_manager_client_installed.nasl", "hcl_bigfix_client_nix_installed.nbin", "hcl_bigfix_client_mac_installed.nbin");
  script_require_keys("installed_sw/HCL BigFix Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'HCL BigFix Client');

var constraints = [
  {'min_version' : '9.5',  'fixed_version' : '9.5.20'},
  {'min_version' : '10.0', 'fixed_version' : '10.0.7'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
