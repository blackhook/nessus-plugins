#TRUSTED 4c57e4da3e8694ab5911f1d0bf3ccabe65a20fa8c6d89a8b81a58671a116369b2d0db36e0f4118c85fd9032e5416109dc08c1be4b50eb0542c00e469694cee330271290448cdc4c7d3871da0337f11cec0efb75da907688c8eb8fe19d7bcc78269a403157c4738778676588fcd7e078c539c922073b291cd48e5c7c225ab2c1e43ff2349f09a406e2f036643af1bdb04166162b5d47b6245cee5d373b5682ec0471428de29ceaadf68b2bf25331f306809618097fc625c98985544fa5f655aa950cc8adb4f9a47cf1e14dcf5b170f690b5289ff1a9db5c7f482b756d160381fda86bad931f95d41a97e860c1f602d4225ba0d5449423b4a16ab9ee0030d176929b56f68331a53ba7d28c03159958a7f877f6fea95dd2efa5f4265154aa884a7f4ca825136efd67b199ad05ae725507df4f8167b8415dea95389d429afe3189e38dcdfdfcc1bc8a639aac09419e118e8ff82ca07e27e4d99667fc2c29b4598b86171acb00a1cb9902d81760d77dcfd0595a3bf0ab0ffd231d7ef44866174e58fbdc980e29cb6ff52a5c667423cc3fa7313025fa4679a877ec394b08d6badeadd8e654e9b9659af38bed9f0284d38d07fc004168eda0c1d3d2b1abae883c41d84f150760a29153b6efd8ee86e5d29f54901972e4156416542740374ac79c5c7dee5f2a76180b4ce020235d1d0a5167f9d4b031c46e050280d7a1a22bf72cf64981
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138354);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2019-1617");
  script_bugtraq_id(107336);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk44504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-npv-dos");

  script_name(english:"Nexus 9000 Series Switches Standalone NX-OS Mode Fibre Channel over Ethernet NPV DoS Vulnerability (cisco-sa-20190306-nxos-npv-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a denial of service (DoS) vulnerability 
exists in Fibre Channel over Ethernet N-port Virtualization due to incorrect processing of FCoE packets. 
An unauthenticated, adjacent attacker can exploit this issue, via sending a stream of FCoE frames, 
to cause the system to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-npv-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d825de1");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk44504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk44504");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^((90[0-9][0-9])|(30[0-9][0-9]))')
  audit(AUDIT_HOST_NOT, 'affected');
var buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
if (empty_or_null(buf))
  audit(AUDIT_HOST_NOT, 'affected');
else if (buf !~ "N9K-(C92160YC-X|C9272Q|C9236C|C93180YC-EX|X9732C-EX|C93180LC-EX|C93180YC-FX|X9736C-FX)")
  audit(AUDIT_HOST_NOT, 'affected');
  
var version_list = make_list(
  '9.2(1)',
  '7.0(3)IX1(2a)',
  '7.0(3)IX1(2)',
  '7.0(3)I7(4)',
  '7.0(3)I7(3)',
  '7.0(3)I7(2)',
  '7.0(3)I7(1)',
  '7.0(3)I6(2)',
  '7.0(3)I6(1)',
  '7.0(3)I5(2)',
  '7.0(3)I5(1)'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['vpc_alive_adjacency'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk44504'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
