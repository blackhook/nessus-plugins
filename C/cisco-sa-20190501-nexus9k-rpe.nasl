#TRUSTED abc25786194a7c038c8c98700a2a590d777b1e5bafaf52ad96f45c41a2ea69d4e562e97eff72b0a7fe3f34ba62dfd5d7aa0be92c5e7195048f709de7dea1107250f642009171b39203f14589ee2f7fcb3e9e469bc9da268a1247e9d75aaefbcda127a345ccadaf8ba138cda081849da54ac4624e3bf07ac55e16b38ea71f99be2f435fe7db834382eebaad884aeba7893ff62104074f8501c3171bb275892a53e00ca0ae9e689386d7129800b8c3ee9915e1ba291ac6076b01133c9bdb26568e6427b67bba4276a9753fe4434bbe07a83f0a5f182d70161921311abd0861c8e510d2877068328d9fcd9ad02841a430c375be3f2507f4e96a93476ba1c7fca7b94d0f4cf015a2efc7897a125885d64da371368cd3ac159a98641f118e146c0e93d7209e3599a62ed44f26eda7a98719a70a03771c0616f0745f63ec54598834b8941fc9e3a73b75f1599ec46821917f1f22bb13de152e36a08bf76f65751df291dc624ae8da56bc4eec8225bb2c489f7ca77609f44f4a028eddd1c7dd56ca32ea178bf217fd90ffd13619568debb4721fb028beb7be83000fd6411f7df55807ec17b483ed475df6949b2bc3dcf6fabc1069a1cb43e413e4d432f7a85f864da26feb52300e1ac7f189c7efd9cbb57b303ab049bf79507094797e3f85821a73c9f70727eafef8d1727aae1f6fa7ebe96e37c044d4b6fb41ba0556da87a1f4be3d13
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137074);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2019-1803");
  script_bugtraq_id(108136);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo72253");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-nexus9k-rpe");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Root Privilege Escalation Vulnerability (cisco-sa-20190501-nexus9k-rpe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20190501-nexus9k-rpe)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by an 
elevation of privilege vulnerability exists in the filesystem management due to improper file permissions. 
An authenticated, local attacker can exploit this, via a crafted command, to gain root privileges.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-nexus9k-rpe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?950f103d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo72253");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo72253");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^(90[0-9][0-9])' || empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '13.2(6i)'},
  {'min_ver' : '14.0', 'fix_ver' : '14.1(1i)'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo72253'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);