#TRUSTED 36e5e110207b0a7144f72325102c527ac684aef7e72b7cd7d28974ce1b25c9473c9fee963c6ee346be9a059875a5b7e5765bcb5e4b5c131bbd944ac0c480d1dca764261f113565ef39c4e7ed521fb0afbc566b7377ba1c9d6043c66839f2f9b69420caae9ee07d81d24d864c47a470b68a98dabe7589ccbe49181eab5e563f665c78c83de46c4925a732f495bfa4dada3cbb32987ac4e92df0a37b1774a5577952dba1a0305624aa68336a10129a5bf5469759096e50069365a1b2cb533100f0b0a880ab79966b8d970deb391e7b06b1275992acbeda7b4cef9829f9a0787ef469a8e8a0e979e056c76404f7187fc42b1e86606e83149115a1838004557d1fe87311e1d028cb4976b99de2a2dd3c640daf88d3ce76e87e0b67f91bf13be8b528cf64cfb806129ebb83d51178be4748ee2a3b2d93841649257702923090a07f8ad8ec4e1574ef59fba7711c4c9915753390fbf26d3c3bc7cb86ee184842d1b05120cbc49bf4eceba670cd84b07e3f7954bf6c4829651846223645ed9ce3ff8b8ef719c0f07d77e76d6d131937f65f020b0e9c3b6f4c1fde153ba274dad954c16ee87a3ca02743bec627823758a3e6ab2d88e6897070a6953be6ce94985785e04d1c96a1909c773bad302b3d859c078c9b66a3b09008c20acde2ac08a1a9a5cc33761d0ff9279996ff022b36d032dccbf3d217510405a1930baf163cf90e16a625
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166052);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/13");

  script_cve_id("CVE-2022-20856");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa92678");
  script_xref(name:"CISCO-SA", value:"cisco-sa-c9800-mob-dos-342YAc6J");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family CAPWAP Mobility DoS (cisco-sa-c9800-mob-dos-342YAc6J)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the processing of Control and Provisioning of Wireless Access Points (CAPWAP) Mobility messages in 
Cisco IOS XE Wireless Controller Software for the Catalyst 9000 Family could allow an unauthenticated, remote attacker 
to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to a logic error and 
improper management of resources related to the handling of CAPWAP Mobility messages. An attacker could exploit this 
vulnerability by sending crafted CAPWAP Mobility packets to an affected device. A successful exploit could allow the 
attacker to exhaust resources on the affected device. This would cause the device to reload, resulting in a DoS 
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-mob-dos-342YAc6J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e25b12f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa92678");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa92678");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20856");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(664);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300|9400|9500|9800")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.7.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['show_wireless_mobility_summary']];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa92678',
  'cmds'    , make_list('show wireless mobility summary') 
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
