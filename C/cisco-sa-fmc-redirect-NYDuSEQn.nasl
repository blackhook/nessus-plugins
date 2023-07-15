#TRUSTED 39a1abbfaae919a86b600d6e1d0716d5364a20729e8dc57ca96ca7d422ec72087dc7ab30ff4e72f29ec8bd1cbb557ab8afcdf0173a31ecfff31decbb9a6c6ce7a29def9c5ffd31211ebb95fe8c4be84c95dc3deb7219e0a05661406ba1a60148407dc16e29334538f80c4ca442ce3b6666f903a2e54bd71569479b0dad610f061b9b31e020e6c5935e0346e2b3754b7874fc0e51c4684ab3c3e50d764e7fa3b79f5d54af0592a395d6673ef3b654f93bb65878ea7389dbebe14a6930e8f6422d987fed6c0799334328434bce31b800f504ff555fc66b665af813bd24af15385010920ba0afbec91ea69e210e07e9e4e4e05e6bd7390cd47a64ba3011b95c74b703c90e1702566e661b2ca8152e78de55dadb2c1e42f421955a06b8b44ba3ff4253194652b743bcfb35975169c8e0811205e234dab73ddeef9723f3fb25687ac1da43d4c626c624c469849c8d7aed0060b066d7253b90e4f62d2ec027b2d7326b8450bd3f702c37e77302879c9f58c857f9f42a6f4978521aecdbbd180db33b7e0bfc2f5448b60b311323fc3ae6b0d0ef3ba5b35bf56a20e6a199ee39da4081f24e7eedf8cd5121cab54fd8806ffaaa80728009472cdb22aae171dba9dc1a40a332c05b7fc0144c18dae9a99a52027e185ec6a00f2ab6ab0a178f41b6a80635e23193fe30d2e308511787fe8187f2ee2d66a1516805392a559c28fe25026aa969
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148381);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/09");

  script_cve_id("CVE-2020-3558");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs71766");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-redirect-NYDuSEQn");

  script_name(english:"Cisco Firepower Management Center Software Open Redirect (cisco-sa-fmc-redirect-NYDuSEQn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the web-based management interface of Cisco Firepower Management Center (FMC) 
Software is affected by an open redirect vulnerability due to improper input validation of the parameters of an HTTP 
request. An unauthenticated, remote attacker can exploit this by intercepting an HTTP request from a user which could 
allow the attacker to modify the HTTP request to cause the interface to redirect the user to a specific, malicious URL. 
This type of vulnerability is known as an open redirect attack and is used in phishing attacks that get users to 
unknowingly visit malicious sites.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-redirect-NYDuSEQn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?074f4fe5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs71766");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs71766");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3558");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(601);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version' : '6.2.0',  'max_version' : '6.2.3.16',  'fixed_display' : 'See vendor advisory'},
  {'min_version' : '6.3.0',  'max_version' : '6.3.0.5',  'fixed_display' : 'See vendor advisory'},
  {'min_version' : '6.4.0',  'max_version' : '6.4.0.9',  'fixed_display' : 'See vendor advisory'},
  {'min_version' : '6.5.0',  'max_version' : '6.5.0.4',  'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
