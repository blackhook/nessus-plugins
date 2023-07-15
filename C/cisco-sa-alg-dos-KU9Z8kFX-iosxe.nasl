#TRUSTED a3145df7e28b962c4ebc45e49fe61b0d814a1bc4add2e80ad04e844b9241349d856ba1c5124adcb888234148b1ba244040d323270f26a92fb3a19dbd97260ce92e429fb650e5898482b868f144d6d96fc535195eb3092d65a35ec94d99efddffc59b7db7dd0fc0504030f7d191ad4715f1411d5e5d92cf8fff7e98336bf3c5c2ffb51901275d7b537d616529a864d5d62db91be92f6cdc1fb61e8c49155500aa40da208af57b46154cf5775f2735a45a25af906ca9f864c944fdc70521b96f07ebc76f0a12d85ca1fd6f45c3f014f0e77dc83ca493c83b46ab568516dd549bffd2b072bb39100e9082ab35a8642e5dba0833a70517c0d5ab48f7a584be1ce69de528f3226706e3f12213954990a6e8ad4a6b3671e15522153030f7ba7885c7a335f536bd2bb4a31405688de0bacf30f8b065d76cd761cf4fdb277339e7bd0995b9c036888b3fe6c67951e48f27f9f0e34aba2604299fb2c328ee152cd393fd09b70e45d0e0f74a45b35f479fb122424d0a600ee95fe4d0b09191af95dc21dd72d13df653858f2a5ed5026f60ce72aaa17b61b5d4ead1c1bb5e96b3d11839d21818cb588671ff4f6b3ccd4c6f82e3ffd6b94f897de06297ab0df44d776d9b6e70cf06d0457559e3ce27a5f03e41f7be110f40b3ad0c03159dbb3e17d8cb33a3e686aff45658f35bc93506442d9aa9f90c0829d1b5c716249234d7663ecfd2dce9
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165762);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id("CVE-2022-20837");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa78096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-alg-dos-KU9Z8kFX");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software DNS NAT Protocol Application Layer Gateway DoS (cisco-sa-alg-dos-KU9Z8kFX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the DNS application layer gateway (ALG) functionality that is used by Network Address Translation 
(NAT) in Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload. 
This vulnerability is due to a logic error that occurs when an affected device inspects certain TCP DNS packets. An 
attacker could exploit this vulnerability by sending crafted DNS packets through the affected device that is 
performing NAT for DNS packets. A successful exploit could allow the attacker to cause the device to reload, resulting 
in a denial of service (DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-alg-dos-KU9Z8kFX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89f41eff");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa78096");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa78096");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20837");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

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
if (model !~ "(ASR.*[12][0-9]{2}-X|Catalyst\s*C*8500-12X)")
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a'
);

# note dns_alg_for_tcp regex all_absent while show_ip_nat_statistics regex is all_present
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['show_ip_nat_statistics'], 
                         WORKAROUND_CONFIG['dns_alg_for_tcp'], {'require_all_generic_workarounds':TRUE}];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa78096',
  'cmds'    , make_list('show ip nat statistics', 'show running-config | include ip nat service dns')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
