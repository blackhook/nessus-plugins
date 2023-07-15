#TRUSTED 1dd5b22cb4f041c21b687025ef1d1f9842af542417e2a29fedc8c581ba67cde304bd9fabf46895672075c9a87e3081b06408aa31b3c749f092e604f8b1f0b577ecf39dfc7688103eb8c7f2c8e4a8aafc852d0be74d292cd614c805ee939bb85fc5e417c3040dd7abbf9202b3dc7701c9ef10d59e15c56cfe6264ba15d4f4ab6d8f938d5ca2f961b96a78d3be84f50088b027cf7ef741be1362dad269aba689ed12fc0450671a41e6cded443da76da9759ccdf12f0bfa00f13846f7347632128e6373151f72cf77d19b912be8e12436da93ea8aca65197421651d8c262afb21e49650c84b09fb3151df6a99ecb1e824237a47c92b6b9d642ac770e50aa06346ce588606f2e4c45ed87db211484102bdc134b6a3e01bd855d3248c344fa004803aa136dc34a794c9233c4d93958390ebd6f33262589bac544208465ed66c3d9e28173025eb24fd917e42b23dfbd2a747184561d71e32b164fa94209521ca6b119f71e607380f18c08b41d9dc881d0e44b7e5170279279450150be9780de910d3c3c79d9863442c00a47636c3fdec7727f34a08a956a7688e68e0d98c4bb68c7c9f463bb930496e732d1a4996b2c47982bca870bf909c65be5943d0ce120a89805e5e5671d658ba2ce921e82780553836289a102c99d19a6fb94275902e9cb53d8d9c0e47914bbd831e16486e881555c15c2002dedbba5cbec68d76a78bc3fab9a6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132074);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-15375", "CVE-2018-15376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy10473");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc82464");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ir800-memwrite");

  script_name(english:"Cisco IOS Software for Cisco 800 Series Industrial Integrated Services Routers Arbitrary Memory Write (cisco-sa-20180926-ir800-memwrite)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by arbitrary memory write vulnerabilities in the
embedded test subsystem due to the presence of certain test commands that were intended to be available only in
internal development builds of the affected software. An authenticated, local attacker can exploit this, by using these
commands on an affected device, to write arbitrary values to arbitrary locations in the memory space of an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ir800-memwrite
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?729a4459");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy10473");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc82464");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvc82464 and CSCuy10473.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# Vulnerable model list contains all the 800 series routers
if (product_info['model'] !~ "^ISR8\d{2}([^0-9]|$)")
  audit(AUDIT_HOST_NOT, 'affected');

version_list = make_list(
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M6',
  '15.5(3)M5a',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.6(2)SP3b',
  '15.3(3)JD15',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.3(3)JDA15',
  '15.3(3)JI',
  '12.2(6)I1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuy10473, CSCvc82464'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
