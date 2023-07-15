#TRUSTED 58453024e519bcd2de3456aac302614f0fd282748a0925bd4edccb892b1e9c659c8fc18cd6dc633736e2c958c69bd2c27746622843a73284eca3c3a39510aa9eb24c823fa1844e5712b3632bc04465acede05c25f18ba880626eb05c6af6f44eb5614d3016f9937fe60b6824c99ccde00124a3f8474a3eefb832ef2b6e6059a00270059e9dba125c1846129f6f7eaad25eb65633ff54a56069f387bad020afe561b716b3b18775413878d774b813d2cd235625673a6d5ab8edc48c41f3c3582507fdb0c71ab5fabb4e03789d963697092ecbee55f6077e037213ecb38294fe9a68d9227256e0c317514960b8df9174f05100a24bbf28250bb78472da4baaedd433aa202da1c080686e081b5ca67b8c30321b2629f02f56141fb6c38210f446fde420eeb7c41295f2414f0c882eb2bcd34cd39ed92444f25d5d5a5393618b66852f4691353dc2d098509630b38d00fddb2f7720aaa50a77876c5b9b05fdaa1ac5d7e19f4607e505a505e27e1495d9c945f053d340ffd088d1fab8be275022e8c9f4a6e4618a429be9bc0accc2fd88180c1ff271b97520cb4f47712be7557b3dca58e49df25aeb3ced973635cf88959c68f457e8cb4b0d25297dd793c1ee5e3e5fd31e75744f18ed989a95cd59f6d7478bfcd17ef6d75e71d6fe70d044679e2bed9c6654869306b96752c2852fcdf2026d452596dd93bc6b0735a42cd30715bb87
#TRUST-RSA-SHA256 2dc235856292dd365265eb8e730ac05dd5760a98c05238c6675caf95717df2731c43b302a15072ef80adc2ab5f4e01d3f0b0a8dc68390c96088958fb4cad6a542bf6ab2d182a244beb4727279c73e32bc87f96c6dc8a44330ebbdf6ee23baf9232437c0aeac2467a3551610eda1e3320c23ab71d650b246a1655dc5567a71842b0f1370f00591d8de4b7383ee8be52b53ea75b717f703e06157ccb81c9f2546a9b0da70e25ef2d46a9ec1f2766e190f57a58e7f2ec5af74e9ae7bb9284b30358afdad2c3bd87fdf8fef06f116973c9094a5fbc783811f184d4b385f1b64571829f14935e42e5540d57a56a433dc001dbe2af1901b391b3544c36bc4d2c8eb6e7dd658e659b281034fac3182cb03c30a08887f4180183bfb6171a473ace0366226c2dca2a8233cfabde6e36882f19111e86005fb33292044593edd83314c076e183cc53b20e2174129f79c09597aa9bd54c817c4778738619d5a47de09fb117d0ee2262c5ac8ee0741a4f10ce12c11319303994d007da7b536a69a26396c124bef3e78f3e2bc02d194fb5e42035940efcfa020d11f2e15d43f67d70d96bdbb41fba77820f84de267277b80daabb67fd2da78b4f8d7fa27a7f2c1440a7b6d8273b7af19e4089aabaf632d8ca6b1d51e3d132f79c43a7912ca088087f05ba63b1bf2668a7c535f24435195d15d319f9e5f043e4e3ec684378ad929a56c7744cc38d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158887);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/26");

  script_cve_id("CVE-2022-20623");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx75912");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-bfd-dos-wGQXrzxn");
  script_xref(name:"IAVA", value:"2022-A-0095");

  script_name(english:"Cisco Nexus 9000 Series Switches Bidirectional Forwarding Detection DoS (cisco-sa-nxos-bfd-dos-wGQXrzxn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software for Cisco Nexus 9000 Series Switches is affected by a 
denial of service vulnerability. The vulnerability exists in the rate limiter for Bidirectional Forwarding Detection 
(BFD) traffic of Cisco NX-OS Software for Cisco Nexus 9000 Series Switches. An unauthenticated, remote attacker can 
exploit this by sending a crafted stream of traffic through the device to cause BFD traffic to be dropped, resulting 
in BFD session flaps. This can cause route instability and dropped traffic and may result in a denial of service (DoS) 
condition. This vulnerability applies on both IPv4 and IPv6 traffic.

Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bfd-dos-wGQXrzxn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbf2e13f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74834");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx75912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx75912");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var workarounds, workaround_params, g1_model, g2_model;

# Cisco Nexus 9000 Series 
if ('Nexus' >!< product_info.device || product_info.model !~ "9[0-9]{3}")
  audit(AUDIT_HOST_NOT, 'an affected model');

# check BFD feature
workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_feature_bfd'];

var m_model = cisco_command_kb_item('Host/Cisco/Config/show_module', 'show module');

if (empty_or_null(m_model))
  audit(AUDIT_HOST_NOT, 'an affected model');

# Cisco Nexus 9200 and 9300 Platform Switches
var model_list1 = make_list(
  'N9K-C92160YC-X',
  'N9K-C92300YC',
  'N9K-C92304QC',
  'N9K-C9232C',
  'N9K-C92348GC-X',
  'N9K-C9236C',
  'N9K-C9272Q',
  'N9K-C93108TC-EX',
  'N9K-C93108TC-FX',
  'N9K-C9316D-GX',
  'N9K-C93180LC-EX',
  'N9K-C93180YC2-FX',
  'N9K-C93180YC-EX',
  'N9K-C93180YC-FX',
  'N9K-C93216TC-FX2',
  'N9K-C93240YC-FX2',
  'N9K-C9332C',
  'N9K-C93360YC-FX2',
  'N9K-C9336C-FX2',
  'N9K-C9348GC-FXP',
  'N9K-C93600CD-GX',
  'N9K-C9364C',
  'N9K-C9364C-GX'
);

# Cisco Nexus 9500 Series Switches
var model_list2 = make_list(
  'N9K-X97160YC-EX',
  'N9K-X97284YC-FX',
  'N9K-X9732C-EX',
  'N9K-X9732C-FX',
  'N9K-X9736C-EX',
  'N9K-X9736C-FX',
  'N9K-X9788TC-FX'
);

var vuln_model = FALSE;
var m_list1 = FALSE;
var m_list2 = FALSE;
var version_list = [];

foreach g1_model (model_list1)
{
  if (g1_model >< m_model)
  {
    vuln_model = TRUE;
    m_list1 = TRUE;
    break;
  }
}

if (!vuln_model)
{
  foreach g2_model (model_list2)
  {
    if (g2_model >< m_model)
    {
      vuln_model = TRUE;
      m_list2 = TRUE;
      break;
    }
  }

  if (!vuln_model)
    audit(AUDIT_HOST_NOT, 'an affected model');
}

if (m_list1)
{
  version_list = make_list(
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)'
  );
}

else if (m_list2)
{
  version_list = make_list(
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(2)',
    '10.2(1q)',
    '10.2(2a)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show feature | include bfd', 'show module'),
  'bug_id'  , 'CSCvx75912'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);

