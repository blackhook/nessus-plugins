#TRUSTED 3fd4609b526d647680df02cabb034d933ec1b937e7463da22629cebc4c4c2f4132241bb08839cd65347bc99170ab737e1dc0005ad2438d1553c36bcc3b729b444c4797a95c10aad2ac94d84d6be122ed8b767fabcbfe10251cfb61f93af8b14564e7ad13610594bb8fa3a54b54038783f33125de2fa458e5bc61ba7249d3d52009e629b1577a88b6398c4c331097f3f8d4878b204e3f31579fc4a833b26b7be1b107e1ec0842f94f732b98610642e1400e5828dfd0b575e6fdc035a2f75758f8c11fd4a1cfcba6435bb346ffcc8ff681940065edeeb01da3832792ac7eb391f89e651a82709ce291d21d2120e76d5caf58481ee06a4740a1ebfc29a08ca483e81158b8f9974ef0cf2ca8899c284184c5c80414424bd6f90ef9116e7cd208cffef36bfa2872293a3155a35df6a2a502516c2d608344ebcc3b8b85b6f6a17b607f9d076d1673b341345ea5882dfdd44c6a18783f4ae3527f6cc4e7ee481ca1097045d0b49100512ae28f34cd4c9a003ad3ac231a00e21662784bf5d08e79c69e21db48c6bc5714f4fd071765d1c2cdb27ee5c50ce6415c328a59439ff34f795d77f918195c423d6308e45bf9323dcddbc6442907f4a137d53a26833c1068831d5de8a1fe7e735735d21de7f30c5528fbc8b790e115ca99c0f3f15ca8fcc75012dc779f19710f1ce96471abfcb36b59f0eaa3127698c5bbc5b55c1081b4e51299d1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128615);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1742");
  script_bugtraq_id(107600);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36797");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-xeid");

  script_name(english:"Cisco IOS XE Software Information Disclosure Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web UI of Cisco
IOS XE Software which allow an unauthenticated, remote attacker to access sensitive configuration information. The
vulnerability is due to improper access control to files within the web UI. An attacker could exploit this vulnerability
by sending a malicious request to an affected device. A successful exploit could allow the attacker to gain access to
sensitive configuration information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-xeid
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beafef95");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36797");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi36797");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi36797',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
