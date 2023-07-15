#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149352);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/12");

  script_cve_id("CVE-2021-1477");
  script_xref(name:"IAVA", value:"2021-A-0211-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu91097");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-iac-pZDMQ4wC");

  script_name(english:"Cisco Firepower Management Center Software Policy (cisco-sa-fmc-iac-pZDMQ4wC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in an access control mechanism of Cisco Firepower Management Center (FMC) Software could allow an
authenticated, remote attacker to access services beyond the scope of their authorization. This vulnerability is due
to insufficient enforcement of access control in the affected software. An attacker could exploit this vulnerability
by directly accessing the internal services of an affected device. A successful exploit could allow the attacker to
overwrite policies and impact the configuration and operation of the affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-iac-pZDMQ4wC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac3d4d67");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu91097");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu91097.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_version' : '0.0', 'max_version' : '6.4.0.11', 'fixed_display' : '6.4.0.12' },
  { 'min_version' : '6.6', 'fixed_version' : '6.6.3',  'fixed_display' : '6.6.4' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.0.2' },
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
