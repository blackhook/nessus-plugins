#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150848);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/21");

  script_cve_id("CVE-2021-1536");
  script_xref(name:"IAVA", value:"2021-A-0282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw48667");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw79311");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw79321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-dll-inject-XNmcSGTU");

  script_name(english:"Cisco Webex Teams for Windows DLL Injection (cisco-sa-webex-dll-inject-XNmcSGTU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Teams for Windows is affected by an dll injection vulnerability 
due to incorrect handling of directory paths at run time. An authenticated, local attacker can exploit this, by 
inserting a configuration file in a specific path in the system, to execute arbitrary code with the privileges of 
another user account.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-webex-teams-dll
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4213ada");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq87642");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_teams");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_teams_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Webex Teams");

  exit(0);
}

include('vcf.inc');

var app = 'Webex Teams';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
     {'min_version': '0.0',  'fixed_version' :'41.3.0.18986' },
     {'min_version': '41.4',  'fixed_version' : '41.4.0.18737' },
     {'min_version': '41.5',  'fixed_version' : '41.5.0.18815' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
