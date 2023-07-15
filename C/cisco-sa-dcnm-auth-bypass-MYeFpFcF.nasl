#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140098);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2020-3522");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu49736");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-auth-bypass-MYeFpFcF");
  script_xref(name:"IAVA", value:"2020-A-0279");

  script_name(english:"Cisco Data Center Network Manager Authorization Bypass (cisco-sa-dcnm-auth-bypass-MYeFpFcF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Data Center Network Manager is affected by a vulnerability in the
web-based management interface because the affected software allows users to access resources that are intended for
administrators only. An authenticated, remote attacker can exploit this, by submitting a crafted URL to an affected
device, in order to access sensitive information and add, delete, and edit certain network configurations in the same
manner as a user with administrative privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-auth-bypass-MYeFpFcF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1933a7ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu49736");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu49736");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.4.1.0', 'fixed_display' : '11.4(1)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);


