#TRUSTED 621b406fb3250b2c76b89714eac91ddf256354aff372bc7ba29955707a880c4dcec989ee0867ca70c199e1dc1ea94b9a7c28238ab912b7491822db7c0caf92308f5963ce1a09dbb562f4d9109c54113cc20a1a97ae187dc813a8529c958cfeb52e6e8f2ccc01758710f54dad1f593141aea1d45f138c42637039b34cc4c30a3e5d301142fd35eb014e58ef37304f47fa539b0387756a5a6938eb5343e14b4443295cdfac27f384636372eadc9b013039d500793ba74d1bb1c52df2e914936e9258760769f97fde821724e5459bbe30a3007d7db7fee9ff96c9bd6b4ea38d5c3779e4060869b859e1aab1b98bbfbc081e25b49e628d28c3a4570bf62d913d1098d5e630f11339af2021d45715867e4e2df8c12e7b1758eee9b767659d8139d25adcac0194dc2a8cbd826be96dbec238b2f71a0da804907c4b4944d80438b114b7ddd605f1c08aa221a8ed6732facd87fd9ade3909653d26e85a4e774aeeaeb9aa25b26f77503e61772bac73decfb9b2f621d1f51d1e91cf7637467b24f2a3c2b11ab606981e85bb959610a08c21d2111675d864822ec424cab4a4b40b26b67cda02bab5abf37c8b5959c6629b47ae95cdfc115c8ca77c96c5a163aa4cd659ade71129bd661771deb69c565de5c839d2ad0a3c242ad13b9f889a395b10dddfe7abf53da91181952770208fee7694478694ad7ff68dcf6dc0c19bfb177d0d9b465b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143217);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3600");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42398");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vepeshlg-tJghOQcA");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-vepeshlg-tJghOQcA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Software is affected by a privilege escalation vulnerability due
to insufficient security controls on the CLI. An authenticated, local attacker can exploit this, by using an affected
CLI utility, to gain root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vepeshlg-tJghOQcA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a12300");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42398");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42398.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3600");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

vuln_ranges = [
  { 'min_ver':'0',      'fix_ver':'20.1.2' },
  { 'min_ver':'20.3.0', 'fix_ver':'20.3.2' }
];

# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42398',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
