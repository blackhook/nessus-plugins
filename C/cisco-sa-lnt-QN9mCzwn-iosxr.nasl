#TRUSTED 9f65e1c347b28baca88f267c917aadfe6764d65a14d056cf2dc0525aad3f901ec51afcc6b2bd09d726905ab10ff2ac320f708614ef0ae9ae3f28f651187defce748d6baf67f5bc2912b5fd12731348c9a25adc25896e6f911ed41613fe92d2b5184ae56d5cc92de613d13ad857aff916e6292af8a1222c3b4fa27a43775bea002b6a0cd547074e8d3539862383c0ba8f9949577a3ed4e16d38a3c9cab173d3b3fbc436d89b27e0fcd69acfb00121f85487ee4f1dfcea9cfc91a71c36132fc6931c37401a86419c2a17d043915a925e2ca178d75ade858cb78105cb335dd914e6b683e77ebb11f66923f43f0d70a2cdffdcaadda269f2e63d02ce65f29bce814ddac40d00a65b8478b89523855c34a3ab314dbeed103d14e3234978bcc6be8b146bb0320672f75614a830c4b1c51c3ebccc291977ccd245812e4164f3f1f327d24264c79d248a99f8f53c3d33edf5c67736fbe2fc990ac0d8ec65fbd489b5a77543947f294f46325cd3a273986ff22cb7a826789b9fe7436c5b12b7831bd7076a7ae3aaae75c861165e6b866131375478fe4e01b315cb76fb6cf7fade2bf0efd0f0013bd3d7ac8f24c6bf7f21e9848160aabbd4ce4117427db547d5aacce681f8f8883b39f011932ff0c08607fff5901a3cf784bab4733a49a5dc023dc7832bdceb22394bb03b22792029a96f9543c650b7598924dc88a746b435f929f5f7e229
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153224);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2021-34708", "CVE-2021-34709");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx38902");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx53064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-lnt-QN9mCzwn");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software for 8000 Network Convergence System 540 Series Routers Image Verification (cisco-sa-lnt-QN9mCzwn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by multiple vulnerabilities in image verification
checks that enables an authenticated, local attacker to execute arbitrary code on the underlying operating system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lnt-QN9mCzwn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b7a493a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74637");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx38902");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx53064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx38902, CSCvx53064");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));

var version_list;

if (
    '8K' >!< model &&
    model !~ "8[0-9]{3}" &&
    ('NCS' >!< model || '540' >!< model)
   )
  audit(AUDIT_DEVICE_NOT_VULN, model);


var version_range, workaround, workaround_params, cmds;
if ('NCS' >< model && '540' >< model)
{
  version_range = [
    {'min_ver' : '0.0', 'fix_ver' : '7.3.2'},
    {'min_ver' : '7.4', 'fix_ver' : '7.4.1'},
  ];
  workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
  workaround_params = make_array('pat', 'LNT');
  cmds = make_list('show version');
}
else
{
  version_range = [
    {'min_ver' : '0.0', 'fix_ver' : '7.3.2'}
  ];
}

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx38902, CSCvx53064',
  'version'  , product_info['version'],
  'fix'      , 'See vendor advisory'
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:version_range
);
