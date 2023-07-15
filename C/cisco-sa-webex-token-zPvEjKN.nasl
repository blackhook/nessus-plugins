#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139544);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2020-3361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu41048");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu43189");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-token-zPvEjKN");
  script_xref(name:"IAVA", value:"2020-A-0273");

  script_name(english:"Cisco Webex Meetings Token Handling Unauthorized Access (cisco-sa-webex-token-zPvEjKN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings is affected by an authorization bypass vulnerability due
to improper handling of authentication tokens. An unauthenticated, remote attacker can exploit this, by sending 
specially crafted requests, to gain the privileges of another registered application user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-token-zPvEjKN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bfcc08c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu41048");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu43189");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu41048 & CSCvu43189");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');

# Detection has no ability to detect MR3 security patches mentioned in part of the advisory.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Webex Meetings');
vcf::check_granularity(app_info:app_info, sig_segments:3);

# Advisory states: "This vulnerability has been fixed in Cisco Webex Meetings. 
# There is no action customers need to take to get the update for Cisco hosted Webex Meetings sites."
fix = 'See vendor advisory';

constraints = [
  {'min_version': '39.5.0', 'max_version': '39.5.25', 'fixed_display':fix},
  {'min_version': '40.4.0', 'max_version': '40.4.10', 'fixed_display':fix},
  {'equal': '40.6.0', 'fixed_version':fix}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

