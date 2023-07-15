#TRUSTED 6c5933cb821cc26e3915917eb6e4d7e04927d36b1e8c83b76eb06104049f8467917ee32d1eae5e3311bd755acdde12d6d2a58992f2ec57fa50185d5ffdb6ceed68b99167c3bca59380bbbdf23c93539be285875d40367f698cce61ee912c472727b17e47f0e732f61aaf741e8d2efe8427267edc009da8c5c5e4bb84642180ae9979670744e4bc512125a4f1e4b71cfde79feedd9d2a01cbd58a3d91d4f857672bb4e5c4432e6a503654570794e62207bb3a01c50a356a489a6429a9d911e9abf500e504269a87c852a9a8dac2f630db4646cd3ba9d5e879001e6072ec5517f7933342a22d3e2c9d2744ad355a691a34656387c75fa584d17a3d88be2cb11d6417414920e455087773b0ceb9f7d7c42af3682cc580c152fac47af2e3f6c79e6a23cff736c85c8d575d0244bc2f7b717f0ad3824925b62b955a63ca796f2183ad2f8e1f24fca8a6336b6a8d898b1e29b887c6a9558c5f9fd5e643a736ef28f8c6f351f5114cb9a4f0c887331a43e46edcb5d662a613503b527d9870cf67a06fff7cad91d2ca5817cb433f0f665cbc69cb186fae2e49ed3b93a727aa196e2b3bcefbd3fc13d7b138d20fd72feb818a04c9102cceae737ce9fa3bb891652e570b9f9932613cae25cd9c96654d0c0b2ff4bf6804ba3918d437f7b0af2ba7fae75134411f9094cde3811e2691c877314023add2bd0a7f66e0c447c0fb301e98647a7a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140221);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/08");

  script_cve_id("CVE-2020-3315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr01675");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr82603");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort_filepolbypass-m4X5DgOP");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-snort_filepolbypass-m4X5DgOP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by vulnerability in the Snort 
detection engine. The vulnerability is due to errors in how the Snort detection engine handles specific HTTP responses.
An unauthenticated, remote attacker can exploit this vulnerability by sending crafted HTTP packets that would flow 
through an affected system. A successful exploit could allow the attacker to bypass the configured file policies and 
deliver a malicious payload to the protected network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort_filepolbypass-m4X5DgOP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff42201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr01675");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr82603");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr01675");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '6.6.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr01675/CSCvr82603',
  'disable_caveat', TRUE
);

  cisco::check_and_report(
  product_info:product_info, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
