#TRUSTED ab22d64b46acb4f5b6a2f7e620316bab8e642764f66de6caec5f41bebd8258ed9368df751106daa3bf66138fa2b7007300a0f9eb588538d7e511375e56f503bf10929dcbe0feeeb35c9a3e7bcab6d53d344a9115b7f29c7f594e9b3b54d99ec4ea9e0ed30766be5ecd6e583ccd1ddb599078fa63b570e4e7574b976f76dc87f1e7fd4cf93d0f6ca826d2e55be7c4ceed36442c4f885fc45bc532b5b52a442cc0a539b6bb4b13b749bc139795c3278ba41c32512a9d94052f1c94e1c9603f9d5dda80d7730c16b2dcdda91b0e90739bc881fbf93c92634824cf1e77b4a08ea081699de2a9a9aa3f7e2688be173274708be5076a9b08c72e3ab713b1c1b393b18d36412cc955d2464b60f247364949dc07c8a8dfc02c72d29a47d52fedb52475e67e8c5c56a36349192af3592c045672b92ade31d3e9c9db0baa95beee0ec6903a7b20a812efb34570bd685ce92721672e1fcddb78f4455468b13e9a212af16e48914640b09e9b527c29add029cd274732817e1378c922d2f4174ca918939f8719146c39c65ec15477c4ecfbb9063605846d13a4f4a99e132d1be6dd242fe7c1670b6582dd81d1f7eb3fa4273d324eb02f72370b7757d240116435b1f083a5af6dfff269247ffd9764d3a8a25355c6a4f82cdfcca0bd02cccfe3359a98ca4d4c0fdc56e1ad324221815013bbf8461479b26946b9c0034a352af98507cdc42148ce
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148962);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1483");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw93084");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-xml-ext-entity-q6Z7uVUg");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage XXE (cisco-sa-vman-xml-ext-entity-q6Z7uVUg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-xml-ext-entity-q6Z7uVUg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef37efa5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw93084");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw93084");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1483");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw93084',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
