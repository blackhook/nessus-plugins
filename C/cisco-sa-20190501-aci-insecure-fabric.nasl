#TRUSTED 89fac4d87300686bd1dfc80f328eaf5de22b318d4e02698bd3270cb34e4032553318ad56165e850af5efca1fe05e4adac827f1b6cd109045d1264c5a20be2564b215e0c2c6058820a158908ee05c8fbe4ca664b8ad9e051fcd076fcbccdd418d7076bf9f14a6a67d8dec50901dc882a18c44066aa5a1dbd68149c49fb3ff204ab22fe2a563c3f6ce8b76ae0f8b62517750ebca21eb6eda9149dc2fdff8d56ff4b1a07521c1ccc84c9fbd1282ed247483eb03658bc7acf87fb0b47c3e19ea53375ea312ea94d99cca2f8864da3a0a2b399ef1c1d197b4ac3df018860a42aebdcd301953e7594a45a1f1532b880b63aeaed7ac5019746ca80285be9953b5f385dd4ef1c40256dce33ac09253e0e924f8f224b25a89097db8bc6320fef92c31363986cd2770056edbe4c8dcd143a52598aa88688e09f55caa7b96191a9aacafb607982ca79b7e140eeaf23b893237f6eb95b400558c15f4736941720c27cdd55c3b60cd8afa63452cfd389a630ca508b07b621920f121d5563ad3d14f49d89c7105a7fbd71e36510faafc435fa4e4271111527e335746730470b89b636cfed144d368a7ef129ce38b673bf6420b2a93fdc6ac6558a20c98b8f37aaac6152f6409ae3caa0d70a84aebc52c387f318c880495471567dfa9fdc4a1a4a5f805e4c08d0e8ca0abde58679a1a6b4ae1a3edbb1ff30b0e00864984059fda46f1dfb0645907
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2019-1590");
  script_bugtraq_id(108133);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn09791");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-aci-insecure-fabric");

  script_name(english:"Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Insecure Fabric Authentication Vulnerability (cisco-sa-20190501-aci-insecure-fabric)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20190501-aci-insecure-fabric)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by an 
insecure authentication vulnerability in the (TLS) certificate validation due to insufficient validation. 
An unauthenticated, remote attacker can exploit this, via certificate manipulation, to gain root privileges.

 Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-aci-insecure-fabric
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa077983");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn09791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn09791");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1590");

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
  {'min_ver' : '0.0', 'fix_ver' : '14.1(1i)'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn09791'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);