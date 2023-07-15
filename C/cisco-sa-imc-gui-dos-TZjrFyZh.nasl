#TRUSTED 7694d643da4309aa5ff3a4265f6583a585c36157de171683b050fa225bd9f5cdc6fa3c7083fc5c71dd35a37f29130769768be226f903c069a9a47b86319000fcc25042e5af9b5bb4e34b2d5f14d4e572497a1fdc4acde89753060e07c1c69fdc627ea8fed47911017cb31764ad5fe5c006b845738290af6d35382ef4385d1c0234c88f943ffafe5373823d218df34b5ba25360cc92359997ec1dd59e0d7ca8b8325501a95cedf404646e086fdde12c30d6ab4a4831a585fd0d454b8864f577b9582e8a715c1b815a4aa462ddfe7bc0374f0f520dcf3d235cd786aeca60ad93b9be33856b97b17b823a86dbae8dbe0fe0d3311fcb401b1fd4e04083889ea465d122405a6acda0641857d3818f77d5c8855d233a76f48b3f870917e57d819f593767f6d394662ac84ebc245440bab8a5c37c15648c421a2de5fcd4c5fcf7c15a2d9eb692318caa70b8035e218443f078585c23a910a36f3b4a69795ecff6aa544b4ac9ee1c153951a9084d23be3a7d1edcf3bdfb20a114e94e7f69a7b8d85e51c18f82ae646eaed5bf6b88e7b6c1d15d129ec9f1beb85c160df5a827525e97941ba0931eb52cff156e08ecbc704c62be2f875da45a72f0bfd61684d27f53cf8e1a5168a36eb95fa4a9784778506a905d2d0198229e45b9227d75daa06f1da60564d44c0aebee7f628ee6ce3f34e34fcb4565f58ae4ce305c860042b5e6d9339caf
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154343);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2021-34736");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy91321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imc-gui-dos-TZjrFyZh");
  script_xref(name:"IAVA", value:"2021-A-0492");

  script_name(english:"Cisco Integrated Management Controller GUI DoS (cisco-sa-imc-gui-dos-TZjrFyZh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller is affected by a denial of service 
(DoS) vulnerability in its web-based management interface due to insufficient validation of user-supplied input. An 
unauthenticated, remote attacker can exploit this issue, by sending crafted HTTP requests to an affected device, to 
cause the application to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imc-gui-dos-TZjrFyZh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f90719c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy91321");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy91321");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

if (empty_or_null(product_info.model) || product_info.model !~ "^UCS [CS]")
  audit(AUDIT_HOST_NOT, 'an affected series');

var vuln_ranges = [];
if (product_info.model =~ "^UCS C")
{
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(2g)'},
    {'min_ver': '4.2', 'fix_ver': '4.2(1b)'} 
  ];
}
else # UCS S
{
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(3e)'},
  ];
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy91321',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);