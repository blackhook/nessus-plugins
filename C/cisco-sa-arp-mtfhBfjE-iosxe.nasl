#TRUSTED 31e7fae9431280c1b8fb4050ceffbb7090597242ac99c222279ca34e2727f768371c41fd11133acb7f25f9449db81dfea9d7588ec28b7614301e20e42da51712a7708477572114c2feab5ef5bbfe410a5d3c68243aaff61dae052aa5995cde8871b4837114a3b297993776cace89cb6c10deb6776e85590a6977d3e3aaf5dd25de6acc5f15b932d836120aaab822329382bce59debe83e15e7ec08d0b68d13ec1c563fcb1991f9480fa86e42a23522d1dbb332e0e08be77cafa3b7874a5b82790204d3117279bbeb3285ba06234e8dac456319511bb0f120e549a20bd4c2c02fbfb9707c047254aa90ec1225548a7686756a2aa21839a39442f74a24a4a6abfd0fcb7fcf789250894e9a46e89b566a70dcef5e7ef453d45b2ae06e340293258788b53437dc53472133136e469e2ff7ac7becd685dc321eb5de35716a7eca55de2a81f80807efd0aaaa06d5847398810a460220785629d42c4c02be88da43d858f397f5c80127f5a102606b21175157feabc40c2807d5e8a2b94cdc80eec9ad977e0943ba10b9dbb46de3f6cd26a00d9fdde4606fa13cabf6613badd9b094e64a8c2102eee5b295d4d7cc81c508e1136e41cbcc1e2b0f3e9b64b643f5670552b4cd3311668e46d0397f6b11d64d219864271941e847de009b28ce20eee3adf31bf3e2ab7bae4276bd9ad99fdddcf552f3d729024ead5d806c57b16548cfdcf59d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148222);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-1377");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv75175");
  script_xref(name:"CISCO-SA", value:"cisco-sa-arp-mtfhBfjE");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software ARP Resource Management Exhaustion Denial of Service (cisco-sa-arp-mtfhBfjE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in Address Resolution Protocol (ARP) management of Cisco IOS XE Software could allow an unauthenticated,
remote attacker to prevent an affected device from resolving ARP entries for legitimate hosts on the connected subnets.
This vulnerability exists because ARP entries are mismanaged. An attacker could exploit this vulnerability by
continuously sending traffic that results in incomplete ARP entries. A successful exploit could allow the attacker to
cause ARP requests on the device to be unsuccessful for legitimate hosts, resulting in a denial of service (DoS)
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-arp-mtfhBfjE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39afa1f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv75175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv75175");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.8E',
  '3.6.9E',
  '3.6.9aE',
  '3.6.10E',
  '3.7.5E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '3.16.4S',
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
  '3.16.10aS',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
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
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.2',
  '17.3.2a'
);

reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv75175',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
