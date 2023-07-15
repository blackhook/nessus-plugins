#TRUSTED 5fd4f4abc390e681a4027ca1c1f81d1c9645eaa4b5d9fdd80e9fb253edee169622ff441a0cb15327a61087ee38ae7fcd4ca237441578a3fda4eecfcec7e4503d51a71b657002dcf16a0766562557bc0eec1854be02f77f0d2d90a79d5e7b1b79f1e21fdf3242da45a48752add2afb90b35ef1adf1fe241b4c6f7314f06ea709b9f38e99daacbc2395152fee12160cb72e3a2d8f92ed8af3b38c7b7b2d5838b3ba80b9d651b1bec14ef8d309d142c32065d0137f5e68ca26e381e04e445383d06b2cdf37ee5fadfd10c34b36dbda884c2cc082b39acbebb0af00b3c8857c90e2e967352e417af2087f2e9858aba66a6629375c582e7cd99c178ca15f9a0f79e83688d8fb26e3664d024db9669b52549883eeab929f909807bbd063318ffd107584bdd303643002f4db657d6627f2bc696af4f3c68f30a78c5732f938719f9d57da82ef0d6417303e66e1e807127ebf5e424f9ceafe4a59aeefb841a638d588daf7d01b873369d627e4a6c59ab8d83836ee9a4b9e031ff89954f6b3eb15cde4d5af253403ad1e7a58bba524c68e1e0e9cc5fc0293c32043bb6709d48d8ff1add7d0a338e0ba254d03696e7166ce8fe8a591a6375f20873fccacdabcdb230fd3587cea853712579f7c759570a604b8438a7ec6ebfd9ad8b3cbc83234d000f55d45226e8307e6dfe6c6aa2b3a1fa0617b92226523cbc7390075c1ab92142c3e34bd8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119844);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2018-15465");
  script_bugtraq_id(106256);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53531");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181219-asa-privesc");
  script_xref(name:"TRA", value:"TRA-2018-46");

  script_name(english:"Cisco ASA Privilege Escalation Vulnerability (cisco-sa-20181219-asa-privesc)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
a privilege escalation vulnerability in web management interface due
to improper validation of user privileges. An authenticated, remote
attacker can exploit, by sending specific HTTP requests via HTTPS, to
gain elevated privileges. Please see the included Cisco BIDs and Cisco
Security Advisories for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181219-asa-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?391d8efe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20181219-asa-privesc.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4.4.29'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.20'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.3.18'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.36'},
  {'min_ver' : '9.10', 'fix_ver' : '9.10.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ASA_HTTP_Server'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm53531"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
