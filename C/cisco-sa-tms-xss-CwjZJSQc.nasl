#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154438);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-34760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy52960");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tms-xss-CwjZJSQc");
  script_xref(name:"IAVA", value:"2021-A-0501");

  script_name(english:"Cisco TelePresence Management Suite Stored XSS (cisco-sa-tms-xss-CwjZJSQc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Management Suite is affected by a stored cross-site 
scripting (XSS) vulnerability in its web-based management interface due to improper validation of user-supplied input 
before returning it to users. An authenticated, remote attacker can exploit this to execute arbitrary script code in 
a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tms-xss-CwjZJSQc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c5dba00");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy52960");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy52960");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_management_suite_detect.nbin", "cisco_telepresence_management_suite_installed.nbin");
  script_require_keys("installed_sw/Cisco Telepresence Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco Telepresence Management Suite');

var constraints = [{'fixed_version': '15.13.2'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE, 
  flags:{'xss':TRUE}
);
