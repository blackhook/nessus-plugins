#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ae.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49020);
 script_version("1.18");
 script_cve_id("CVE-2008-3805", "CVE-2008-3806");
 script_bugtraq_id(31363);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg15342");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh29217");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-ipc");

 script_name(english:"Cisco 10000, uBR10012, uBR7200 Series Devices IPC Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Cisco 10000, uBR10012 and uBR7200 series devices use a User Datagram
Protocol (UDP) based Inter-Process Communication (IPC) channel that is
externally reachable. An attacker could exploit this vulnerability to
cause a denial of service (DoS) condition on affected devices. No other
platforms are affected.
 Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6a69a5de");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ae.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?30e1472b");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ipc."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3806");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

 script_end_attributes();
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2023 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/device_model");
 exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info= cisco::get_product_info(name:'Cisco IOS');
var model = get_kb_item_or_exit("Host/Cisco/device_model");
var modelToLower = tolower(model);
var modelPattern = ("c10k|ubr10|ubr72");

if (model !~ modelPattern)
 audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list = make_list(
  '12.4(1c)'
  '12.4(1b)',
  '12.4(1a)',
  '12.4(1)',
  '12.3(14)YX5',
  '12.3(7)XI9',
  '12.3(7)XI8d',
  '12.3(7)XI8c',
  '12.3(7)XI8a',
  '12.3(7)XI8',
  '12.3(7)XI7b',
  '12.3(7)XI7a',
  '12.3(7)XI7',
  '12.3(7)XI10',
  '12.3(14)T2',
  '12.3(14)T1',
  '12.3(14)T',
  '12.3(21)BC',
  '12.3(17b)BC5',
  '12.3(17b)BC4',
  '12.3(17b)BC3',
  '12.3(17a)BC2',
  '12.3(17a)BC1',
  '12.3(17a)BC',
  '12.3(13a)BC6',
  '12.3(13a)BC5',
  '12.3(13a)BC4',
  '12.3(13a)BC3',
  '12.3(13a)BC2',
  '12.3(13a)BC1',
  '12.3(13a)BC',
  '12.2(28)ZX',
  '12.2(28b)ZV1',
  '12.2(28)ZV2',
  '12.2(28)VZ',
  '12.2(33)SRC1',
  '12.2(33)SRC',
  '12.2(33)SCA',
  '12.2(33)SB',
  '12.2(31)SB9',
  '12.2(31)SB8',
  '12.2(31)SB7',
  '12.2(31)SB6',
  '12.2(31)SB5',
  '12.2(31)SB3x',
  '12.2(31)SB3',
  '12.2(31)SB2',
  '12.2(31)SB12',
  '12.2(31)SB11',
  '12.2(31)SB10',
  '12.2(28)SB6',
  '12.2(28)SB5',
  '12.2(28)SB4',
  '12.2(28)SB3',
  '12.2(28)SB2',
  '12.2(28)SB',
  '12.0(31)S1',
  '12.0(31)S',
  '12.0(30)S5',
  '12.0(30)S4',
  '12.0(30)S3',
  '12.0(28)S6',
  '12.0(28)S5',
  '12.0(28)S4',
  '12.0(28)S3',
  '12.0(27)S5'
);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCsg15342, CSCsh29217',
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);