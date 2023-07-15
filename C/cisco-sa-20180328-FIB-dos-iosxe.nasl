#TRUSTED a9573ecf429ec65ae36df744603980fe52304221da48574841d2a5bbcee36acb1c49e1c5634c48cc61dadf57b02c48b44900c4aff958c47b702b755572e50b22653d8113dfbf912f1710956ef03df659ddc98f0131dbc29b178e00cdda19cf4aa74c565378bae3e88fab637cbf40cc23c27985937ad62115628651aeaec3f2f309cea4420cd1f5f1268f38b2885d6e096a20b4749a2fe6f20caabdaa4dc16118081c2ddf078526b5f0254110689c8a00557fcebec2a5b0625a6f9088c34b5d0b54a9d547ee714b4b4bae04dd52f96457939ab58ce8c596d4614baa7df030c807489cfe1a0b1386b1843a2f3e0cdbcb191a84126dca2ca26273eef8022bd3385d36339859926814865a9d9c5824e151288021f77a6619dedd41dcf6129cec9af6e314a9127e8e7d41fe9d4052a6b55a4f8bff85c0f6c5a2d58d3f7b9e836523519982e32045ca3aa199911bcf972676b90756d2a1468f78a2e3cae73ce5ff68bed45733dedca2c9192fb3c75dc0a9520d0773c242d4ca36dad1a200b629ff9f2b1bf7a7609bdbe8b72bed44b565a904b61b42fe3883199b660b5578b202e425dd1d0b00b8bd5c3f463d63024dd1dfe40840a83e5c65c2db9bedee884c32c0e598422b4d642456ed32efe672f624d639f2ca0add5fa645d662b61ee1b34deab5674750e8f0f4768fb7083147bb757e292eb74c7eca256607e0f476113ca147344f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132698);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2018-0189");
  script_bugtraq_id(103548);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva91655");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-FIB-dos");

  script_name(english:"Cisco IOS XE Software Forwarding Information Base DoS (cisco-sa-20180328-FIB-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Forwarding Information Base code due to a limitation in the way the FIB is internally representing recursive
routes. An unauthenticated, network attacker can exploit this, by injecting routes into the routing protocol that have
a specific recursive pattern, provided that the attacker is in a position on the network that provides the ability to
inject a number of recursive routs with a specific pattern. An exploit allows the attacker to cause an affected device
to reload, creating a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-FIB-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9af64740");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva91655");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCva91655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Converted from IOS versions found on the BID page to IOS XE versions, according to cisco_ios_xe_version.nasl
version_list = make_list(
  '3.5.0E',
  '3.6.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.0E',
  '3.11.0S',
  '3.12.0S',
  '3.12.0aS',
  '3.13.6S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0.1S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.16.0S',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva91655',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
