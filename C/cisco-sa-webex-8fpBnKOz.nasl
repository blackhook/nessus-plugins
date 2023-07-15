#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150502);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2021-1544");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx88066");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-8fpBnKOz");
  script_xref(name:"IAVA", value:"2021-A-0282");

  script_name(english:"Cisco Webex Meetings Client Software Logging Information Disclosure Vulnerability (cisco-sa-webex-8fpBnKOz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-webex-8fpBnKOz)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings is affected by a information disclosure vulnerability.
This vulnerability is due to insufficient protection of sensitive participant information. An unauthenticated, remote
attacker could exploit this vulnerability by browsing the Webex roster. A successful exploit could allow the attacker
to gain access to files containing the logged details.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-8fpBnKOz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96d2ea8b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx88066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx88066");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1544");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_meetings_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Webex Meetings', port:port, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'fixed_version' : '41.4.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
