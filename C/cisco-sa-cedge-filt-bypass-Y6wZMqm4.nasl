#TRUSTED 69b7ea0be0c2586781f96f436c44f7df511b9e3692db4cb7e91945914f36e8c548f4772a7e3bc0baf13a2bfa316646c696520c860165213158a2d95692ec4f28e5a3cbe713ba047dafa6a22e708cfa22a53e1b9f4ba42f11f3d5d6b6596e17fb6640e99e2b033ddca78fdc1a560f3c805bfe33e2382043b51cac48ab7ce243a594bf47b1187d0f0eced21022ca3bb60668d1814d65b86898437b5a36bc0168a7b3975bd6b553ab9469c386b21c73e703cb367bf52450dc2047f415b97ae671f45e25ef7a1e53a354ba54663060ef29d41a1534ccdf6f825bb33a808805a59aee2610ba3bf4a16d2456ec0363769818c6ece6f817fc5188e4511ac10aa0b191085f39305bde4f31354c9dd58b88ced6c2dd482fb4141a82b142445e73224ad6b9ffea3abd3fc873fd78d22b6800a5574fb5f89356aff976bc1b753ee8342bb90355c045ffc298b666b43a518d75a58decb81009c87cb140ba79eac541c3baf3c113614848ad863cbeefa959f7ecd763333002016829534a4a1bdc35f295683000f90a02c3bcb8e61fed4393322698357ad7985f28262fd7c807ac52e400ce2b3819e6d9dc07bdd192e94aabf954ce89639142b7eb09e53f5578828d76b685e4b2f9711a42f64be95426cba8532cb8c1c499d0c3817d97b2cf1e8df76aabe952aebfdbae5fbcae9d31126e2b16ef9a313a9e2fa043985f13cddb7b77d2e9aa9581
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143155);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3444");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw12895");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cedge-filt-bypass-Y6wZMqm4");
  script_xref(name:"IAVA", value:"2020-A-0540");

  script_name(english:"Cisco IOS XE SD-WAN Software Packet Filtering Bypass (cisco-sa-cedge-filt-bypass-Y6wZMqm4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a packet filtering bypass vulnerability.
The vulnerability is due to improper traffic filtering conditions on an affected device. An unauthenticated, remote
attacker could exploit this vulnerability by crafting a malicious TCP packet with specific characteristics and sending
it to a targeted device. A successful exploit could allow the attacker to bypass the L3 and L4 traffic filters and
inject an arbitrary packet into the network.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cedge-filt-bypass-Y6wZMqm4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bafac99");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw12895");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw12895");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.10.4',
  '16.10.5',
  '16.11.1a',
  '16.12.2r',
  '16.12.3',
  '16.12.4'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw12895',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
