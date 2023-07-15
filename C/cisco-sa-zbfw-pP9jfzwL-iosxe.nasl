#TRUSTED 55de57e060c1c496a8ea241c87f8f5a66ed2ef7a013773a3ab0eaec84d22b3fa5d2470f49046fb7d895e07abc38a6e4dc6b519344488fe40f3729344bebfed1903b107f087b4f0eb7804a42f9cef5c9e71c647f39d81563556dc0b87e3d0388d9df480fb8201c943ef7938cc5e067aeb2aa4779a5d34c64afc32191f51981c1ef7bf8a9ab5ebc893dcd6445f52364220ab72227315eb94cf280a5fc9617cdefdd579f441a0d35ebb515f048a0e9a6d770c5b0cabf085839954830a3c1b9050a0e80515eefe11d57470f7e040d29a0d51838acf845c5fb7a0c96c2923b10eeda5b9bcaf5dd7cdaae1e29e007e36185b757288cf9ebf8c2c8840bb2365b2f7f6e9384b27950201d9eca8dcca24abc945139a7b858308f404dabed0cb5898d531d3bf8a98fcfaf6253d42f31b513271ae97149f718ff61a4d04955bfc15fdabc6c6f14bf6a1d250e6e05342b864958fd8b27786cad68e1868c7836d7faca59be91c8a83622c71e5b79ce443f53cb600cc3ed639fc5cd2481e781b1e19f3782787d0beb4d032bce0045b31cdc69d50a108ca258f8f3a5903b9abb7ca6c14800b0fa1e0005b1b66900108b1a1b69502a607eca94bb1f25c97553c4c8cf0d77431c6ca641167b79ef9f0c8e3623e35a1c999f45648b65658a58577bbbae2e57251b823bc954037a198f67f2e8b6451eb9ebe124c6d572360ef6131e050fb29cf41afe5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153694);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/06");

  script_cve_id("CVE-2021-1625");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv78028");
  script_xref(name:"CISCO-SA", value:"cisco-sa-zbfw-pP9jfzwL");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software Zone Based Policy Firewall ICMP UDP Inspection (cisco-sa-zbfw-pP9jfzwL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Zone-Based Policy Firewall feature of Cisco IOS XE Software could allow an unauthenticated,
remote attacker to prevent the Zone-Based Policy Firewall from correctly classifying traffic. This vulnerability
exists because ICMP and UDP responder-to-initiator flows are not inspected when the Zone-Based Policy Firewall has
either Unified Threat Defense (UTD) or Application Quality of Experience (AppQoE) configured. An attacker could
exploit this vulnerability by attempting to send UDP or ICMP flows through the network. A successful exploit could
allow the attacker to inject traffic through the Zone-Based Policy Firewall, resulting in traffic being dropped
because it is incorrectly classified or in incorrect reporting figures being produced by high-speed logging (HSL).

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-pP9jfzwL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?025c1b54");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv78028");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv78028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# can't detect snort currently
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var version_list=make_list(
  '3.16.0S',
  '3.16.0cS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.1s',
  '16.12.2',
  '16.12.2r',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.2a',
  '17.3.1',
  '17.3.1a',
  '17.3.2',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv78028',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
