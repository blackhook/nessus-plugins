#TRUSTED a421cec61217af4af1e8d7b00fb1bffae718d80c37f7056f0edd02ae92e39caa2dd0cac1ae05e1b3cffac14b91ee3456125f00be9100899fccddc0c270d481e5351e2c5228098d26434e8ba5e8ec4814e42205a9685cdb9950e17f0f6419d991be075fc2fbceca338eee889a5aca2bc6c52a2f36931994d3908c0467a50b3351acbca1af0c350ec4f52b18589a64c2d4a4e9878077e07e3c51a06872d7a0a29f75fbbc6006713d8af704b3600db857fe642703ac623dd00992e6b2eee489db23085f0875aa52c8b1957f7a507873262d8c23e00fcdd2dba3a7fa46f495b528295db796c418c0cfa5f76fc7dadb2e704a19e8e3f6886bad33dfecbcbee80cb96a3af3ed27e28cfdd69c8ea2883491a1f6a5ef528c1893716de85226c3302ff31363341d7d1e3ad40b7e1c6b1dc64392359127977f678eff59bf85d9f290febc9fcaf0f80c43d4c50dfe4e372cf963d68db1a37bcb8b37007afa08b3aded8651b85a7f446d1294ea5943a4ceadf0dc37ca3b77883218810ee709e4ef279ff14ca9c3ff96e7d197a948b09e8bd0eb05658926d745261aed5a1a3120dd50de349b4b80ef2de085fb45d4214d3819a628a1fd54dc0bd53ab6003a635a174c39e4956173b1419a750a2a311a2cd76572439955162f3375123115aa198cbed5a98709ef53a36c9864d5b6d6d052b67d5d9613d2989830db142bc30d136803c0d23238cb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147651);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2019-12619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01888");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi56327");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59629");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-sdwan-sqlinj");

  script_name(english:"Cisco SD-WAN Solution SQLI (cisco-sa-20200122-sdwan-sqlinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-20200122-sdwan-sqlinj)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an SQL injection (SQLI) vulnerability in
the web interface due to insufficient validation of user-supplied input. An authenticated, remote attacker can exploit
this, by sending crafted input that includes SQL statements to an affected system, in order to execute arbitrary SQL
queries.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-sdwan-sqlinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c44be9a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01888");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi56327");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59629");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi59629, CSCvi56327, and CSCvi01888.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'17.2.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi01888, CSCvi56327, CSCvi59629',
  'fix'      , 'See vendor advisory',
  'sqli'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
