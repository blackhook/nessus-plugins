#TRUSTED a386a7b62ccb79179e3fcead8a47e3938dd912f4bfc563bc1ac599c93d3ec73b64d14e7cb9ae2e71bd07d7e0d5b0ab252f7c0ee1e157bee96a2845e75e16bf337458aa9d480a6daec7a97b11a71d2cf78680030d1b738390f084173300bc6d43c09fde3391cec74b3251105f160e5b042ac61512c9a7ad4e7dd3c302a116b1f81fafc268e74dd969c658a7f746e518f73e8214a8a6c624cc3b95eb106a03b59af38cc5abb5a9bc3d5371bf621a2dc0133b96a3e47241f2d65bf6403dfdc7629356d8adc2d478d14b2c8e3554f17ef0012080a5cb1fdb76f45924e26fad66e5068024338d2ea7c06abc30b6834bba99b791196273d5029dd296dfd37801d5f5781601db97aa07f1f53ec15fb54d41bb8acdc88319b637f3c444f23e70a2233cc341cb9217eb7e57e0976107f4ebb393be3592fb15a10695a8b5095e9386dd4f62f759d98335b05f147de410423d1e3b231cc15053dea6bed3804c811f3a14530a834684705aefc363dd4b22544e7a02df47811d1764b70e69f1c0c3a3a336ee1b4c57314e1380bf44078de2fdad1824b26ee839821e03ad2190a41d1e6a4bf1caf2cedaaec45d01ab9cd4485c4ad6ef33d4e14d520facade38c9571302561ba092164b02151f4c012600711656270bb6c4b75f9fc5fb6517b3dde787ed86d2c230df14a8479ab5e0df698189359b1d995a6287c90f18bf66f7c8c984f4a36f5db
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149789);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1352");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv51476");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-decnet-dos-cuPWDkyL");

  script_name(english:"Cisco IOS XE Software DECnet Phase IV/OSI DoS (cisco-sa-iosxe-decnet-dos-cuPWDkyL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the DECnet Phase IV
and DECnet/OSI protocol processing. This vulnerability allows an unauthenticated, adjacent attacker to cause a denial of
service (DoS) condition on an affected device. The vulnerability is due to insufficient input validation of DECnet
traffic that is received by an affected device. An attacker could exploit this vulnerability by sending DECnet traffic
to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting
in a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-decnet-dos-cuPWDkyL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4578be34");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv51476");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv51476");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(823);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['decnet']);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvv51476',
  'version'  , product_info['version'],
  'cmds'     , make_list('show decnet interface')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
