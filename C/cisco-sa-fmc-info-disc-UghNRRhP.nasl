#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167397);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2022-20941");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa85709");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-info-disc-UghNRRhP");
  script_xref(name:"IAVA", value:"2022-A-0486");

  script_name(english:"Cisco Firepower Management Center Software Information Disclosure (cisco-sa-fmc-info-disc-UghNRRhP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the remote host is prior to tested version. It is,
therefore, affected by an information disclosure vulnerability due to missing authorization and insufficient entropy for
certain resources in the web-based management interface, that could allow an unauthenticated, remote attacker to 
retrieve sensitive information from an affected device by sending a series of HTTPS requests to it.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-info-disc-UghNRRhP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfe39a51");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa85709");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa85709");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(334);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:2);
var constraints = [
  {'equal': '6.1.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.1.0.7', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.2.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.6', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.7', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.8', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.9', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.10', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.11', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.12', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.13', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.14', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.15', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.16', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.17', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.2.3.18', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.3.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.6', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.7', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.8', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.9', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.10', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.11', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.12', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.13', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.14', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.4.0.15', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.5.0.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.5', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.5.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.5.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.6.7', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.7.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.7.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.7.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '6.7.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.1.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.2', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.2.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.3', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.0.4', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.1.0', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.1.0.1', 'fixed_display': 'See vendor advisory'},
  {'equal': '7.1.0.2', 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
