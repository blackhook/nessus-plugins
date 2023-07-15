##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163057);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/13");

  script_cve_id("CVE-2022-20752");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa91887");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-timing-JVbHECOK");
  script_xref(name:"IAVA", value:"2022-A-0266");

  script_name(english:"Cisco Unity Connection Timing Attack (cisco-sa-ucm-timing-JVbHECOK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unity Connection installed on the remote device is version 12.5(1) prior to 12.5(1)SU6 or 14
prior to 14SU1. It is, therefore, affected by a timing attack due to insufficient protection of a system password.
An unauthenticated remote attacker can exploit this vulnerability to determine a sensitive system password.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-timing-JVbHECOK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95893106");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa91887");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa91887");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(208);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  # https://software.cisco.com/download/home/286313379/type/286319533/release/12.5(1)SU6?i=!pp
  {'min_version': '12.5.1', 'fixed_version': '12.5.1.16900.29', 'fixed_display': '12.5(1)SU6'},
  # https://software.cisco.com/download/home/286328409/type/286319533/release/14SU1
  {'min_version': '14.0', 'fixed_version': '14.0.1.11900.128', 'fixed_display': '14SU1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
