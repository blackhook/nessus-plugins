#TRUSTED 16adc3dcf28fff43e56abd607f0fda654cb95f88041bc76c509ec44212c457e6221b016adc348385b314698e66238b82289372e4566580ccc58d66bc9b6ecf634981b5d949a7984e352a9e3fb34081335acb1cafcdf62c720f6d95caa212111e60b3ce3058b60fd31adddb547f71e3dff79e530fd7940e5f1ec0b5da310836025af9fb8ba7737ab60261a61a0735bc20ed01eef036627570c15f0bb7577a03bf8325a8ca63f764a06d3d25ca3436601941cc62b08622d391e007282ec6026446f6bae6363997a5c19e4b08c740e9226c3aeeb0b0f828227e03bfe3ef408885721da459e4bdb03487ccba1c76b259e502692049bb32c38bd8fdf6b24cb310678c73239cc6e5e42d1db053be41eb3d0d1278c3c25bd20837fa3a2ae835c83744adec39a6c402b1b7b5dfef246b5750c1b5cf6fc9d694f6a0b352ca51ce2b999bad35fbe9fb94f18d422d133b92a51fdfd1cd0c9059380d932baff9de9822bcfc372c12843168efedadd790761a36f947d295489c1da1f68b6eb43b91750a387994b7747b25e9f6011add6bf1091b735d0b6b4ed283c1326dd92a06e12a5b37cd12e407915b98baf45fa749e7f136b5c6ffb2be2b8ece59022a342bfb46f8093407689068bc6334d120d0a11e6ca678320e5f2d342d0456bb912cb1fd886e5c400491655e9687ed55ae932558738e830cb7eab05a16632587b9ed0c160814c8b9c8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148101);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2021-1373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv41608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-dos-2OA3JgKS");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family CAPWAP Denial of Service (cisco-sa-ewlc-capwap-dos-2OA3JgKS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-2OA3JgKS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6d909d5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv41608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv41608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500')) &&
    (model !~ 'cat' || (model !~ '9800')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.3',
  '17.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv41608',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
