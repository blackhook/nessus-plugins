#TRUSTED 032ad50a4da959484715021866e1140db826f1b0032619650e443fa35db1db0bfe6efce9c9697cc58b053454a259e5ea930c49289bee021659474c519bf126cdb1ca411769d44b20d22d5bb7a70b00d5c13f51d4d6f6656833699d74ea30d381e4bde7d73de2d0abce4472ca9fc677d67807be4c348a2ae46a0e8323533953c937a82af9a5440253c9d553be9a4a277a4f0c5d0dd3b2b4774b06414ba186e5fe6087e46f55e14b33e5fa465ed116a4a9cf264ef95a15117aad7515fd10c966af62bd21aad1fb236fb68cbb67d20f6d463c3433c835349af9d44644d30e4e2ec418f036e6bf08066d3e366f4dfcbcfc96740cfa6b1b55f0349fea27c60592ce23638b776684f6418701e662b184c651d54d03fe8363c5b13f1b6ffd0de1f54749652a617c1a8f7192237ddab812cc7d3039d85ec0ded090acbd18e58540e7f2643072b7f1f5ded146aaac536d949c14015b19c8589cc5559b54c5cb6267e0f17968e352c9983c947d3a1f9d94d24874f31c51af3c567e8e5024329c97a21bc0c5d4af8af98a69afbf6969c6707cfdd0522502ba7b7897eb857b8fcb5de8528f738cc9c6281bb2711063df2b100d8c6a384ddf5f10c091f43f11735fc9dd78fc24a9794fb3f1eae3bd42f0b7440105a2c2aabb72409c7bed0e70e2c8dbc0168789bebb3598d65b822ad174397a9a733126b200cd92874b33e49bd37ffbd197996a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129733);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-12656");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo19668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp28143");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp28178");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq86542");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iox");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco IOx Application Environment DoS Vulnerability (cisco-sa-20190925-iox)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a denial of service vulnerability in the IOx application
environment of multiple Cisco platforms. This is due to a Transport Layer Security (TLS) implementation issue. A remote
attacker can exploit this by sending specially crafted TLS packets to the IOx web server on an affected device, causing
the IOx web server to stop processing HTTPS requests.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iox
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfca13f5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo19668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42730");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp28143");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp28178");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq86542");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo19668, CSCvo42730, CSCvp28143, CSCvp28178, or
CSCvq86542");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');
model = product_info.model;

bug_ids = 'CSCvo19668, CSCvo42730, CSCvp28143, CSCvp28178, CSCvq86542';

if (model !~ '^IC3000([^0-9]|$)' &&
    model !~ 'IR510([^0-9]|$)' &&
    model !~ 'CGR.*[^0-9]1[0-9]{3}([^0-9]|$)' &&
    'IE-4000-' >!< model
    )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2a',
  '15.2(6)E3'
);

if (model !~ 'IR510([^0-9]|$)')
{
  workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
  workaround_params = make_list();

  reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , bug_ids
  );
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['monit_summary'];

  reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , bug_ids,
  'cmds'     , make_list('monit summary')
  );
}

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
