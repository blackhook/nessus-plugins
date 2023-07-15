#TRUSTED 916d4b02a947d463e20245f9cac659cfd8981cef3046fdaa0cbbccfc4e6fb5468014af14b7df518b789c48bbeaae9534147809b2c821db63ad19b85124a2f5beeffbdda50dacc1869e9c83b7961eb71aa4288bdef490fcb0ce5f0df2dc97f4dbbd915148a999654aeae806da2ee95229fb6dfd946818983dcdd32c77151c1545c3ef25edd44b9ca13b6d37de81d16ba131917060db7f35913bfeaf2c12414fd7f185b92c623259a0f524f894bd57d9aab18b66e263317d3f9ce2d940bcf4767f2fdb1747c32006e6ef65ea6fff2b930e4e91963df943c678d82b6e95539fa065dd976029cb19fd57ba13ad0f5fcf480014238bf287fec9d4a268481093e5aed5cc76f163ffe1f4f1461e2a4a75e62017dea47b3f986d39beeda3d0bcdc350b8b7fbde59303fbde285881b896013a621dfc91ed5d99b13df05b9d0b12c52a4ea13b32f3550c6b32d2565c3d5821b75fc53bee239b74bfe32766e38734365f460d7ba394188619223bd13c205f7c03b884af311d9fd83831c03b4b3322a4c617ede4726bdbd021e32f9862b09a8a7fccd97f6e1248ece3df8a8efbbd230a6e733f06e11570c6808fcee3182ce1ba62d65cde7f24b4d60ec61f8f433b1edb78b8c3784b465080c9caf56f0491a4da2b38789d0d512e21b71d5496d60b00e6181db66d0740e55dc0c86fdc89b75c188f53c00b55f235c1dcf65acb5ab1f61d9fbc79
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130765);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2016-6384");
  script_bugtraq_id(93209);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux04257");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-h323");

  script_name(english:"Cisco IOS XE Software H.323 Message Validation DoS (cisco-sa-20160928-h323)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the H.323 subsystem due
to a failure to properly validate certain fields in an H.323 protocol suite message. An unauthenticated, remote attacker
may exploit this, by sending a malicious message, causing an affected device to attempt to access an invalid memory
region, crash, and restart. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-h323
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b960210");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-56513");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux04257");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCux04257");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.1xcS',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.2bS',
  '3.17.0S',
  '16.2.1',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['h323']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCux04257',
  'cmds'     , make_list('show process cpu')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
    );
