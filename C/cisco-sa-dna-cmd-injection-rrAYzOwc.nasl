#TRUSTED 3a0aa95efca937e9903edad9e42a811d3fcb68001954dc07517c9aaea4b5eb12fce6caddf6eac197b90cda24ce3d50e4ea205b312f917def2fba8ef49c2337d06f702d9f51d1c5e037484d974498311d657b2cbc5471a5047388dc866e66db53df5c8cc0390e31ccbfa4d049f5d0b3653baabc8a4fab3ec075b0d7e4e933e0d373ba1de5db7acc70f58edae58be258debdcc6099ef2944fb4a19464117bd999eba212fa0c96edb737678cbb3040a003b0e2a67f616f6feaf494944a0358e8da04b4e9bd2e11bb13de33fc5132e3e9335f794b1b0ecf46643e20f9d075bed80a1f1b435da0570d5df0afc9ffa8eb9f4b5a922e5d326e6b5f0165efcf59aad4c5de3fd001a30e88285986e2d57463ed133b415d72cc349cfb001709888360659aeb729d90416cb1c0ea71537d9b97fe055ec07e800c5c673b1325b20023adb2aa504c8092f1b294bb4b62d346437b052ca88b6c8c2cb234939657aa48e299f327d91cc7d1912eee8acc2cff400202ab47c78a08716de86f01c49f7d17e586aa830ad85d41dba1a1a03f5721c364c44b479e941177df52fb1172e1f17c4482919de6654021bc86fb5b7637d9ba4e9b3069241d242ba4448b4e5af4450462717c3eae8bdc43401620c81e55a4891b8368cbefed15cc143fa4c46bf401757c298514fa2c7c330eb53f7eff7272ee76746e55a7ef55979ee5ddc5c4434db73a4bde3b6
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143424);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/03");

  script_cve_id("CVE-2020-3586");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv25495");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dna-cmd-injection-rrAYzOwc");

  script_name(english:"Cisco DNA Spaces Connector Command Injection Vulnerability (cisco-sa-dna-cmd-injection-rrAYzOwc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in Cisco DNA Spaces Connector due to insufficient validation of user-supplied
input in the web-based management interface. An unauthenticated, remote attacker can exploit this, by sending crafted
HTTP requests to the web-based management interface, to execute arbitrary commands on the underling operating system
with privileges of the web-based management application.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dna-cmd-injection-rrAYzOwc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecf1a2e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv25495");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv25495");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:dna_spaces%3a_connector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_dna_spaces_connector_web_detect.nbin");
  script_require_keys("Cisco/DNA Spaces Connector/Version", "Cisco/DNA Spaces Connector/Port");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'DNA Spaces Connector');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '2.3' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv25495',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
