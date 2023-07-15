#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168647);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_cve_id("CVE-2022-20934");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-fxos-cmd-inj-Q9bLNsrK");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc02133");
  script_xref(name:"IAVA", value:"2022-A-0486");

  script_name(english:"Cisco FXOS Software Command Injection (cisco-sa-fxos-cmdinj-TxcLNZNH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CLI of Cisco FXOS Software could allow an authenticated, local attacker to inject
arbitrary commands that are executed with root privileges. The attacker would need to have Administrator
privileges on the device. This vulnerability is due to insufficient input validation of commands supplied
by the user. An attacker could exploit this vulnerability by authenticating to a device and submitting
crafted input to the affected command. A successful exploit could allow the attacker to execute commands
on the underlying operating system with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-fxos-cmd-inj-Q9bLNsrK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45540201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc02133");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc02133");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'FXOS');

# Vulnerable model list Cisco Firepower 4100 Series / 9300 Security Appliances
if (product_info['model'] !~ "(41[0-9]{2}|9[0-3][0-9]{2})")
    audit(AUDIT_DEVICE_NOT_VULN, 'The ' + product_info['model'] + ' model');

var version_list = [
  '1.1(4.95)',
  '1.1(4.117)',
  '1.1(4.140)',
  '1.1(4.169)',
  '1.1(4.175)',
  '1.1(4.178)',
  '1.1(4.179)',
  '2.0(1.37)',
  '2.0(1.68)',
  '2.0(1.86)',
  '2.0(1.135)',
  '2.0(1.141)',
  '2.0(1.144)',
  '2.0(1.148)',
  '2.0(1.149)',
  '2.0(1.153)',
  '2.0(1.159)',
  '2.0(1.188)',
  '2.0(1.201)',
  '2.0(1.203)',
  '2.0(1.204)',
  '2.0(1.206)',
  '2.1(1.64)',
  '2.1(1.73)',
  '2.1(1.77)',
  '2.1(1.83)',
  '2.1(1.85)',
  '2.1(1.86)',
  '2.1(1.97)',
  '2.1(1.106)',
  '2.1(1.107)',
  '2.1(1.113)',
  '2.1(1.115)',
  '2.1(1.116)',
  '2.2(2.17)',
  '2.2(2.19)',
  '2.2(2.24)',
  '2.2(2.26)',
  '2.2(2.28)',
  '2.2(2.54)',
  '2.2(2.60)',
  '2.2(1.63)',
  '2.2(1.66)',
  '2.2(1.70)',
  '2.2(2.71)',
  '2.2(2.83)',
  '2.2(2.86)',
  '2.2(2.91)',
  '2.2(2.97)',
  '2.2(2.101)',
  '2.2(2.137)',
  '2.2(2.148)',
  '2.2(2.149)',
  '2.3(1.56)',
  '2.3(1.58)',
  '2.3(1.66)',
  '2.3(1.73)',
  '2.3(1.75)',
  '2.3(1.88)',
  '2.3(1.91)',
  '2.3(1.93)',
  '2.3(1.99)',
  '2.3(1.110)',
  '2.3(1.111)',
  '2.3(1.130)',
  '2.3(1.144)',
  '2.3(1.145)',
  '2.3(1.155)',
  '2.3(1.166)',
  '2.3(1.173)',
  '2.3(1.179)',
  '2.3(1.180)',
  '2.3(1.190)',
  '2.3(1.215)',
  '2.3(1.216)',
  '2.3(1.219)',
  '2.4(1.101)',
  '2.4(1.214)',
  '2.4(1.222)',
  '2.4(1.234)',
  '2.4(1.238)',
  '2.4(1.244)',
  '2.4(1.249)',
  '2.4(1.252)',
  '2.4(1.266)',
  '2.4(1.268)',
  '2.4(1.273)',
  '2.6(1.131)',
  '2.6(1.157)',
  '2.6(1.166)',
  '2.6(1.169)',
  '2.6(1.174)',
  '2.6(1.187)',
  '2.6(1.192)',
  '2.6(1.204)',
  '2.6(1.214)',
  '2.6(1.224)',
  '2.6(1.229)',
  '2.6(1.230)',
  '2.6(1.238)',
  '2.6(1.239)',
  '2.6(1.254)',
  '2.7(1.92)',
  '2.7(1.98)',
  '2.7(1.106)',
  '2.7(1.122)',
  '2.7(1.131)',
  '2.7(1.143)',
  '2.8(1.105)',
  '2.8(1.125)',
  '2.8(1.139)',
  '2.8(1.143)',
  '2.8(1.152)',
  '2.8(1.162)',
  '2.8(1.164)',
  '2.8(1.172)',
  '2.9(1.131)',
  '2.9(1.135)',
  '2.9(1.143)',
  '2.9(1.150)',
  '2.9(1.158)',
  '2.10(1.159)',
  '2.10(1.166)',
  '2.10(1.179)',
  '2.11(1.154)'
];

if (product_info['model'] =~ "9[0-3][0-9]{2}") {
  append_element(var:version_list, value:'1.1(1.147)');
  append_element(var:version_list, value:'1.1(1.160)');
  append_element(var:version_list, value:'1.1(2.51)');
  append_element(var:version_list, value:'1.1(2.178)');
  append_element(var:version_list, value:'1.1(3.84)');
  append_element(var:version_list, value:'1.1(3.86)');
  append_element(var:version_list, value:'1.1(3.97)');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwc02133',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
