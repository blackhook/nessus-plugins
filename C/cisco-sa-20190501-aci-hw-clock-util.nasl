#TRUSTED 70c3ab636413bfb8ebc91e876b250ebbec66420760e60114cd8c2b4a1256bf5777cf48b531d5b98ee962cca8928e0eea61a32a2bb7ae7dece6e9be79a9d25544184747779278244e499ca8b929090a657c4f66c3b9f6f9eb9ff2521040d7562abb6e85386481e39ca4f3ef1f3ae7f9b53ace16759f0c872d1f37e6eb5d033503cf111ed9b6c5118cc5f0f13f4cb57156d54bb40ecf1a39a0682860d9fc352bad1e1f24bed250e507c7dc5a9786edd71e0d747168afe7d7f001ae944bed22b9d199159c06f9f449ff9f983e404a73bd32c930b8b416dbd5e58653b7149d75d340d3fac807df6655f9e883d0ce41ab7f6725d18d3889d87632e1e8fb3d2cede56297bf31bea81993930a6cc39a2cd27f9dbd78fe0fcdfe225082a1c6719c473ade26b7fd657fdec38e729ee76638a3151bfae95c45bcd78be0729dd89dde299c203ad91ac0264dc20bf342c743b7ba4444fa804b3aeefb3f673d3a90529d07ba0cb78a77d4c65bd48d541247849f793d4cd7e7544b20a0ffdbfe98f4d442e3d8437396aaa423b2594e55847e9befce3b08d05ad15380e4162983dbee74cf40e8328acc3672747a2585584fb614b1dbd8fa47d4f60e969410d79d9e8e0d4ae4b2032dbf2d70f40366d2cdfb67185b47cd4643cd07ba12b07173038f4dd4f38047350a531ecc87bb20661ab76204406891352115e132256591e8a5f707d416b6092c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137072);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2019-1592");
  script_bugtraq_id(108146);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm64104");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-aci-hw-clock-util");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Privilege Escalation Vulnerability (cisco-sa-20190501-aci-hw-clock-util)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20190501-aci-hw-clock-util)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by an 
elevation of privilege vulnerability in the filesystem management due to insufficent validation of 
user-supplied files. An authenticated, local attacker can exploit this, via creation of a custom file
in a specific directory, to gain root privileges.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-aci-hw-clock-util
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efaa0233");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm64104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm64104");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1592");

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
  'bug_id'   , 'CSCvm64104'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);