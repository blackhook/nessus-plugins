##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146056);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2021-1272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv82444");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-ssrf-F2vX6q5p");
  script_xref(name:"IAVA", value:"2021-A-0048");

  script_name(english:"Cisco Data Center Network Manager Server-Side Request Forgery (cisco-sa-dcnm-ssrf-F2vX6q5p)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the session validation feature of Cisco Data Center Network Manager (DCNM) could allow an
unauthenticated, remote attacker to bypass access controls and conduct a server-side request forgery (SSRF)
attack on a targeted system. This vulnerability is due to insufficient validation of parameters in a specific
HTTP request by an attacker. An attacker could exploit this vulnerability by sending a crafted HTTP request
to an authenticated user of the DCNM web application. A successful exploit could allow the attacker to bypass
access controls and gain unauthorized access to the Device Manager application, which provides access to network
devices managed by the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-ssrf-F2vX6q5p
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87e9f69e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv82444");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco DCNM software releases 11.5(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '11.5.1.0', 'fixed_display' : '11.5(1)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);