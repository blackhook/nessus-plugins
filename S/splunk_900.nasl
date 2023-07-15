##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164076);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id(
    "CVE-2022-32151",
    "CVE-2022-32152",
    "CVE-2022-32153",
    "CVE-2022-32154"
  );
  script_xref(name:"IAVA", value:"2022-A-0251-S");

  script_name(english:"Splunk Enterprise < 9.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to 9.0. It is, therefore, affected by multiple
vulnerabilities.

  - The httplib and urllib Python libraries that Splunk shipped with Splunk Enterprise did not validate
    certificates using the certificate authority (CA) certificate stores by default in Splunk Enterprise
    versions before 9.0. Python 3 client libraries now verify server certificates by default and use the
    appropriate CA certificate stores for each library. Apps and add-ons that include their own HTTP
    libraries are not affected. (CVE-2022-32151)

  - Splunk Enterprise peers in Splunk Enterprise versions before 9.0 did not validate the TLS certificates
    during Splunk-to-Splunk communications by default. Splunk peer communications configured properly with
    valid certificates were not vulnerable. However, an attacker with administrator credentials could add a
    peer without a valid certificate and connections from misconfigured nodes without valid certificates did
    not fail by default. (CVE-2022-32152, CVE-2022-32153)

  - Dashboards in Splunk Enterprise versions before 9.0 might let an attacker inject risky search commands
    into a form token when the token is used in a query in a cross-origin request. The result bypasses SPL
    safeguards for risky commands. Note that the attack is browser-based and an attacker cannot exploit it
    at will. (CVE-2022-32154)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0601.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e830af9");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0602.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad3b9d22");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0603.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6b2548f");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0604.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77bc5700");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 9.0, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32153");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32151");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'fixed_version' : '9.0', 'license': 'Enterprise' }
];

vcf::splunk::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
