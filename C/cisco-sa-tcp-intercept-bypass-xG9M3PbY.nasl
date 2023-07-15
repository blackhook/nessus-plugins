#TRUSTED 67e418f17d5edc3eaba6234dab5a8cef378c45800cdcf6915b5e65a1337727f9e6643053958cbaa1f6149458e543affb78158f78c4584bf56e9eab17eac54e0916d184fbea979c9482232147c2bab547fa3687f831d71cbfcc1526e25ef249f6a7fae6dff0ad53d50e8f5139c3bc92c3a0eec6a537820506ba4825864a822c7b200e866d6ce294fc886517e1bc1641b6c83b0e01d469659f5da425116604f761b3a42f0a5be92760061f1a7add20b27e3896cad4fc58f40689d5d47b5d4d2c8119d8586c0b2e2c22f971a71519d6b0fe786b9091104021aea903da60beefab06e05d18ce58c3161590115dc93f89a2176e89f204705c3b46345ad7d4b41d0794c74cbdfdc89e2377f393dfd0e6d7011d0542643bca213f85fd72a8f844bef87e9f5c5d0fd0f59db22da0f7f07643ee31e951f656aa6ff584fdbfed3ad63382d97497554c6e5fa78d7ce079a82814f10a49dc9777d7335f8269d7fd592a12050bf8337730e5ea28f7b1651086adafee9300c9191e81015a57f468477e3fbe72b728d803157ee1f798b081d2d290f1ec37d5bcad3e75efd702cfc1dcc1cf75b5fe7a41e894ff0818ea73c16c6c326413e384c2187c4c5a44a9176c01f9ea51a00e86fa5bfabdc507fcdbaf7183558fe605ee4e01c81c57f3912d46cd48213252b2fc4f4b90282d3015ed855359ca0ddafd2dadd66ac9e16a12e5d300fae741d998
#TRUST-RSA-SHA256 58630d644daf5951c1935367d240c34774e1f500cffae8f4bc753321177317ecd5141bef9acdfca6fed42a7e3b66ddfe135c02e71fd43310806cf1b46a9f5526e5787efb0b04e7da92a049af798f6ff874927899b89d3bcb8b1c7a06d965669fb7f2f062400fe55165246f5cafd911dfb34badf133fe27e6ea3b054714e19299d33be67465ed6c3a626eb6c32c2dbd79d58965792e957884ffa6f7009b288936b99396b434a79b35691b8b2af0c456891c6f0b696014fd6ba361f832b53787a88f116e41f288f241454669253c4d757535580aa23458a13ae36b89fc281a13b6462ec6913e071a9a60d38b662f69402cefd69d266c7cf84da403adfe30ded8b07615b64b527b75c8f30049c6c277d9852cf30bdfc4250fd07ed6d3d7800c17317be9bca8b076ba74c65cc9721669ef995459db1dbc998e48a4eae12c89e88e48d60674e5a7c32405e4f8fa2fe7a8b084a027c679502113bfe69fb1ec619988d5ac65eda1c7895e9bce77aa166b7b4dbb90d58ab4d17ac4f7eb3dcd2f9ac2a1ee023f2348cc3799adfbaac73582a301e0de79d9c175396c0619686cdf87f5042b028468e84d6a3483eb91deffe51e1d23c219036d15df4ffbd43d56a44dfa22d1a84ed4c9dc1426d39efd3e043261d5a865d2f6195ce4133987e3aa304aee23ce4ea6edc92e6989256cab5d2a31c28f958568704442b5deba5f72b857b0624a7d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152130);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr53058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tcp-intercept-bypass-xG9M3PbY");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Firepower Threat Defense Software TCP Intercept Bypass (cisco-sa-tcp-intercept-bypass-xG9M3PbY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-tcp-intercept-bypass-xG9M3PbY)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a
vulnerability in the TCP Intercept functionality of Cisco Firepower Threat Defense (FTD) Software could allow
an unauthenticated, remote attacker to bypass configured Access Control Policies (including Geolocation) and
Service Polices on an affected system. The vulnerability exists because TCP Intercept is invoked when the
embryonic connection limit is reached, which can cause the underlying detection engine to process the packet
incorrectly. An attacker could exploit this vulnerability by sending a crafted stream of traffic that matches
a policy on which TCP Intercept is configured. A successful exploit could allow the attacker to match on an
incorrect policy, which could allow the traffic to be forwarded when it should be dropped. In addition, the
traffic could incorrectly be dropped.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tcp-intercept-bypass-xG9M3PbY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7ab00f2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr53058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr53058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

# Not checking GUI for workaround
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco Firepower Threat Defense');

var vuln_ranges = [
  { 'min_ver' : '0.0',  'fix_ver': '6.4.0.8' },
  { 'min_ver' : '6.5',  'fix_ver': '6.5.0.4' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr53058',
  'fix'      , '6.4.0.8 / 6.5.0.4 / 6.6.0'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
