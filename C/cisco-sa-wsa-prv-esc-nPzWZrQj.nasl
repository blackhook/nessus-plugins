#TRUSTED 11795677b45f5e390f3a22379564aac27c8c93dd2d31a837b77a2eb74b9b19f6ced06a87edee799fba684b79292ee9bec0e2b062da60ee47d774458896b47e6d113f6f9662e261c8a3bfeff3cc4b949dac598accb01515f641d987f3cd3399f9929818d405dc0d762d9131771d17c2b2469469b4a1406787738ae10261356924eb9f7e3d55cd6a78254b3172fabf61ee9d22b136671e3ed7a35b661feb827ef3dfb0ddb93563590b709e176a3781057115bd3feefc0b169546155424a24ae08b3090eabdcf38323a8654d3fa42c3b7693b5bc8a806ba321fa22d34435c1ba49a3f478c720730db603f0a4d32ade71b7a7b8ab8d9bcb9b1aadc00d28206ef6bd46f6373cc5046acd8758fe251a2f178e3f4038027842f448b1ac458eb555fa8b14f58008c9b67ff0bc69d5fd7ead6e7bbbebd2895fff4b769d0d5743af0fbac43df5f4a8e23b5bd051d7d70c018dc92fd1c1bfdd799b66cb652005170dfc4857ce7884aeb464c33e8a7216030bf3708e59877ff4d72d042727ddef74a0d3cfc56b6a050662adecc1ba9c2d585753e228a7291ebc648fb7833d5b5b286d7d9bed4758049aafa451ab5ce40811b57c66e5f949844a246c44d68e08639c658f625a9a0fdb6f480306d08c7c701f026c40bf3e55e0435fcd1becb5e1e6ff40677677763c3b2a2a62147ced699bd5e4dc82dfd1b2ba862c64c14ffcdd066571e82b15a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143153);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3367");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs65863");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-prv-esc-nPzWZrQj");
  script_xref(name:"IAVA", value:"2020-A-0542-S");

  script_name(english:"Cisco Secure Web Appliance Privilege Escalation (cisco-sa-wsa-prv-esc-nPzWZrQj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-wsa-prv-esc-nPzWZrQj)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by an input-validation flaw
related to the log subscription subsystem that allows an authenticated, local attacker to escalate privileges to root
user via command injection.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-prv-esc-nPzWZrQj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f93d77");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs65863");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs65863");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

# Cisco WSA Release 12.5.1-011 / 11.8.2-009 / 11.7.2-011 and earlier
vuln_ranges = [
  { 'min_ver' : '0.0'  ,'fix_ver' : '11.7.2.011' },
  { 'min_ver' : '11.8' ,'fix_ver' : '11.8.2.009' },
  { 'min_ver' : '12.0' ,'fix_ver' : '12.0.2'     },
  { 'min_ver' : '12.5' ,'fix_ver' : '12.5.1.011' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs65863',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
