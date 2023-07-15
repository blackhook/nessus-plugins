#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155447);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/17");

  script_cve_id("CVE-2021-34750", "CVE-2021-34751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy69730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy72194");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-infodisc-Ft2WVmNU");

  script_name(english:"Cisco Firepower Management Center Software Configuration Information Disclosure Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by multiple vulnerabilities as referenced in 
the cisco-sa-fmc-infodisc-Ft2WVmNU advisory. Multiple information disclosure vulnerabilities exist in the web-based GUI
of Cisco Firepower Management Center (FMC). An authenticated, low-privilege attacker can exploit this issue to view
sensitive configuration parameters in clear text.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-infodisc-Ft2WVmNU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80793a0b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy69730");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy72194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy69730, CSCvy72194");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(317);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'min_version' : '0.0', 'max_version' : '6.4.0.11', 'fixed_display' : '6.4.0.13' },
  { 'min_version' : '6.5', 'fixed_version' : '6.6.5.1'},
  { 'min_version' : '6.7', 'fixed_version' : '6.7.0.3' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);