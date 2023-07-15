#TRUSTED a0be98f51ae2a3c8f5d6938ec0389efd36a27fe8d7285fe5f4478bd0e27c5c2bbc52bad16c62167be9437a02bffb5bc015a23e3ecbb46c3dbe485fc14d9d88545de6177631a6bd385cc467608b48a7df48dfb121514116f3087ecd3e5f65da47d4bf0933ad315ba2a0397701dd7ba8a5b1a247a85a45bc8d3bc9c3516ddbea88368e1bf8f6fe94f7894cf96e18149203e300ada56424bf2720f49fcc5feed91d8a4a5174ff8cbbd62889d707626d42e9bb2c5d137999bac6e93d2900671ce551b27815fc7fe5e80cbf88da91227461f2bd2ed415a390ade9e28aa96166ced088ae556afa9804e1640c3950699c5c9c062c66a3c5b9163ae188c48e7133674a883d635673e49804fe411572c6e03205bcc203ea73c230d6cc855e2d3732679c5d50bef63cb2ca111c3dcbf4a3e24f1281975b642e965aae72c245182dfe9b14b2d6500410e7956b8cfe419c8d15d519d8388e26390c0debeabd52b649f493bb148aa5239e41f3b30ad36f743ede71e6a384f29af054bfb4868b78492b7b488b2e7a569c5f08a0874079f5c2b52e09389725b7d1ddbc0696e4184133fbf3131c83b804a7f2c5600bad41a20ed4d21bced3311db9c847d88d8ba43b012437470f248c9a896de1427dcdc166ec887fd88a9d99fac1a44cefc9ec0d9fcc6c962cec2f6899394e9db715d95c2a90b686654d5f568c62fce2cbcb0d1e4400d1d697de6f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133267);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-15428");
  script_bugtraq_id(105944);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj58445");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-iosxr-dos");

  script_name(english:"Cisco IOS XR Software Border Gateway Protocol DoS (cisco-sa-20181003-iosxr-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability in
its implementation of the Border Gateway Protocol (BGP). This is due to incorrect processing of certain BGP update
messages. An unauthenticated, remote attacker can exploit this, by sending BGP update messages that include a specific,
malformed attribute to be processed by an affected system. A successful exploit allows an attacker to cause the BGP
process to restart, resulting in a DoS condition.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-iosxr-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dc4cd5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj58445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj58445");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

version_list = make_list(
  '6.0.1',
  '6.0.2',
  '6.1.1',
  '6.1.2',
  '6.1.3',
  '6.1.4',
  '6.2.1',
  '6.2.2',
  '6.2.3',
  '6.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj58445'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
