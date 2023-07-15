#TRUSTED 7641edbf70e3b96a6e0e361fa679fa60921c4f53f0f184eb8c50f54da86c7e89fa253348b876427055ab0c2b956e7154627c756a888736c093f250bb1790032d781a2e1ffbd8628fd2ed584db93bfba4cc5f063dec26eb244089870688da2556dbab716d5f6bb14dabbc748da1d172219595ed1b39d9271c621c6fef7006e78bef853bdf749009b863b3db87632577ebf84484891dc1f7f911181f3a196c1739cfa176c81f6a5f551d2a31dba9412de7a295e6199e6be783a3f9841d125d9b02bb345de6328e51d725089c99800f64b86994730aec2ab7fac3755815bb6352e9c5c695bdb743b2f25769e1c697713894a2fe9028f83e7aecf66f88f2f606a9a3f87e20c9a440eb1420393f901af43998f3a52058fc3786bc05bdb519d0a1711345212ac6f27aef65fc301f39f0ec98a30b74e6186485d323a6112d017e37e7d3ef8ff407e3baf8993f8bb5d96f9fca379a606260184e6ea7007692009fd1b9af4f319f02fa336991f89309ffba9e3d876910b5b597c90657e21064dac7508c3cf160f9e2bb2460e904cdd544045e73b0c397011887dd6a2d8e32ff8d8093643d2e15f9033191501888d349fe61c096050f9cfa37af520a8eb74e793fcc4584779dd1c97924b1f97b6f0814a79d705c635901927f3c7236911109d62d126ae6b15d44be93df5ecf5de15ea095207cba16e2cf925c3558d941f38d0313b25a60cd
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147654);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2019-16010");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs09263");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200318-vmanage-xss");

  script_name(english:"Cisco SD-WAN Solution vManage Stored XSS (cisco-sa-20200318-vmanage-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN Solution vManage installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-20200318-vmanage-xss advisory.

  - A vulnerability in the web UI of the Cisco SD-WAN vManage software could allow an authenticated, remote
    attacker to conduct a cross-site scripting (XSS) attack against a user of the web-based management
    interface of the vManage software. The vulnerability is due to insufficient validation of user-supplied
    input by the web-based management interface. An attacker could exploit this vulnerability by persuading a
    user of the interface to click a crafted link. A successful exploit could allow the attacker to execute
    arbitrary script code in the context of the interface or access sensitive, browser-based information.
    (CVE-2019-16010)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200318-vmanage-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efee1316");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs09263");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs09263");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
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
    {'min_ver': '0.0','fix_ver': '19.2.2.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvs09263',
  'version'  , product_info['version'],
  'disable_caveat', TRUE,
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
