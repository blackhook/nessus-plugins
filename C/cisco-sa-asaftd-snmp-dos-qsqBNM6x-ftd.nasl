#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178025);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-20924");
  script_xref(name:"IAVA", value:"2022-A-0487");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb05148");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-snmp-dos-qsqBNM6x");

  script_name(english:"Cisco Firepower Threat Defense Software SNMP DoS (cisco-sa-asaftd-snmp-dos-qsqBNM6x)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial of service (DoS) vulnerability in
the Simple Network Management Protocol (SNMP) feature of Cisco Firepower Threat Defense Software. Due to insufficient
input validation, an authenticated, remote attacker could exploit this vulnerability by sending a crafted SNMP request
to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting
in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-snmp-dos-qsqBNM6x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2665459d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74838");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb05148");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb05148");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20924");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info['model'];
var vuln_versions = NULL;

# Cisco Firepower 1000, 2100, 4100, 9000 Series
if (model =~ "(FPR-?|Firepower)\s*(1[0-9]{3}|1K|21[0-9]{2}|2K|41[0-9]{2}|4K|9[0-9]{3}|9K)")
{
  vuln_versions = make_list(
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco ASA 5500-X Series Firewalls
else if (model =~ "ASA55[0-9]{2}-X")
{
  vuln_versions = make_list(
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3'
  );
}
# Cisco 3000 Series Industrial Security Appliances (ISA)
else if (model =~ "ISA3[0-9]{3}")
{
  vuln_versions = make_list(
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Firepower NGFW Virtual
else if (toupper(model) >< 'NGFW')
{
  vuln_versions = make_list(
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3',
    '7.0.0',
    '7.0.0.1',
    '7.0.1',
    '7.0.1.1',
    '7.0.2',
    '7.0.2.1',
    '7.0.3',
    '7.1.0',
    '7.1.0.1',
    '7.2.0',
    '7.2.0.1'
  );
}
# Cisco Secure Firewall 3100 Series
else if (report_paranoia >= 2)
{
  vuln_versions = make_list(
    '7.1.0',
    '7.1.0.2',
    '7.2.0',
    '7.2.0.1'
  );
}
else audit(AUDIT_HOST_NOT, 'an affected model');

var workarounds, workaround_params;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwb05148',
  'fix'      , 'See vendor advisory'
);

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  reporting.extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['snmp-server'];
  reporting.cmds = make_list('show running-config');
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
