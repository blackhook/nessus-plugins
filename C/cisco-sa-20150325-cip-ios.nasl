#TRUSTED 944c94266949197eba877a93bdc2c71c9b9ead9e5a12632e7faa19fc37e416835a4c51d3ec5ab3c5523433e842f66ff190d7c5af80d7eddac90d0a33e0f3cf66b8a171b61f98caf6becdd236fef512e06a4596b9ade7e6188063ec3db417382380807bfd8c2b0b66ebac7c207a84648ee7ae599fc2254b409f84a30b08e71e3c3c7fa431d2d85915179ef636a9134ddaee6e900ea8696f9055ecbb4679943e4c42dba6ca79202a2bd1f61b2999608d2def742d4ab9552f55b06cdacb1203e40e49ad56f9b03b29b5a2ac5cc83513e80931fc463d228c99b6e03e8fb74182ba3286fd19d9044c1eb353968e139bfd7e0d56500e228e6dfb89bfb0673b1fead37d44bdd2c73cff974e9e027b4fa35968a143349f0901322948639e9d0fb0dccad91dd39bc2d242318467fac2e89b55673c343b206bc681c8a2fa3b4531060f7e127be78934988cf84e2397aa1fde0fff17c3433f0bd4d67ac58e3e59dc226882ba49ff0bcf6493cd88127058414607fec1766ff65a6361a544767c574fb809ed974c021adec8647c34209553752cd435f4076fed809b4518a049c11384e3063f34d3b11ae7a60e5dc5eceeac61d10c05f42f3179eaa2cba89832926f7aef44ec8f852a5185e159d683c499f9894c0c382c8fd17646d1e13a8738e65a5af12f26c4051dd3446bc15cb394cd0d0fec7eacef34394bdcb813708d954e919e8c4cb553
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82571);
  script_version("1.19");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0647", "CVE-2015-0648", "CVE-2015-0649");
  script_bugtraq_id(73334);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum98371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun49658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun63514");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-cip");

  script_name(english:"Cisco IOS Software TCP CIP DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running on the remote device is affected by multiple
flaws in the Common Industrial Protocol (CIP) implementation that allow a remote, unauthenticated attacker to cause a
denial of service (DoS) condition, as follows:

  - A denial of service (device reload) may be triggered via malformed CIP UDP packets. (CVE-2015-0647)

  - A denial of service (memory consumption) may be triggered via crafted CIP TCP packets. (CVE-2015-0648)

  - A denial of service (device reload) may be triggered via malformed CIP TCP packets. (CVE-2015-0640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-cip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dadcf82");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCum98371");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun49658");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun63514");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(44)EX',
  '12.2(44)EX1',
  '12.2(46)SE1',
  '12.2(46)SE2',
  '12.2(50)SE',
  '12.2(50)SE1',
  '12.2(50)SE2',
  '12.2(50)SE3',
  '12.2(50)SE4',
  '12.2(50)SE5',
  '12.2(52)SE',
  '12.2(52)SE1',
  '12.2(55)SE',
  '12.2(55)SE10',
  '12.2(55)SE13',
  '12.2(55)SE3',
  '12.2(55)SE4',
  '12.2(55)SE5',
  '12.2(55)SE6',
  '12.2(55)SE7',
  '12.2(55)SE8',
  '12.2(55)SE9',
  '12.2(58)SE',
  '12.2(58)SE1',
  '12.2(58)SE2',
  '12.4(25e)JAP1m',
  '15.0(1)EY',
  '15.0(1)EY1',
  '15.0(1)EY2',
  '15.0(2)EX2',
  '15.0(2)EX8',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY2',
  '15.0(2)EY3',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE10',
  '15.0(2)SE10a',
  '15.0(2)SE11',
  '15.0(2)SE12',
  '15.0(2)SE13',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.2(1)EY',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)EA',
  '15.2(2)JB1',
  '15.2(2b)E',
  '15.2(3)EA',
  '15.2(4)JAZ',
  '15.2(4)JAZ1',
  '15.3(2)S2',
  '15.3(3)JA',
  '15.3(3)JA1',
  '15.3(3)JA1m',
  '15.3(3)JA1n',
  '15.3(3)JA2',
  '15.3(3)JAA',
  '15.3(3)JAB',
  '15.3(3)JN',
  '15.3(3)JNB',
  '15.6(2)SP3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['cip_enabled']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCun63514, CSCun49658, CSCum98371',
'cmds'     , make_list('show running-config')
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
