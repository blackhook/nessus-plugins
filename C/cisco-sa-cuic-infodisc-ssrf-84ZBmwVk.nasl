#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173300);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2023-20061", "CVE-2023-20062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd01184");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd02972");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cuic-infodisc-ssrf-84ZBmwVk");

  script_name(english:"Cisco Unified Intelligence Center Vulnerabilities (cisco-sa-cuic-infodisc-ssrf-84ZBmwVk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Intelligence Center installed on the remote host is prior to tested version. It is,
therefore, affected by multiple vulnerabilities as referenced in the cisco-sa-cuic-infodisc-ssrf-84ZBmwVk advisory:

  - A vulnerability in the web-based management interface of Cisco Unified Intelligence Center could allow an 
    authenticated, remote attacker to access sensitive information. This vulnerability is due to excessive verbosity 
    in a specific REST API output. An attacker could exploit this vulnerability by sending a crafted HTTP request to 
    an affected device. A successful exploit could allow the attacker to to obtain sensitive data, including hashed 
    credentials for services associated to the affected device. (CVE-2023-20061)

  - A vulnerability in the web-based management interface of Cisco Unified Intelligence Center could allow an 
    authenticated, remote attacker to bypass access controls and conduct a server-side request forgery (SSRF) 
    attack on an affected system. This vulnerability is due to improper input validation for specific HTTP requests. 
    An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected system. A successful 
    exploit could allow the attacker to send arbitrary network requests sourced from the affected system. 
    (CVE-2023-20062)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cuic-infodisc-ssrf-84ZBmwVk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?618a1f72");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd01184");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd02972");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd01184, CSCwd02972");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_intelligence_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_cuic_installed.nbin");
  script_require_keys("installed_sw/Cisco Unified Intelligence Center (CUIC)", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'Cisco Unified Intelligence Center (CUIC)', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'fixed_version':'12.6.2', 'fixed_display':'12.6(2) (Mar 2023) / Bug IDs: CSCwd01184, CSCwd02972' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
