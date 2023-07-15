#TRUSTED 67022ff59cb46f1d56efa1a4dc912a7a4af59bc411f2041689375c32b1b5569373ed295ff5bdd6f1088c415e7e48e2e08d92ee57670b2660585844c12e4e0c4cc9894dde4f7e21f8d1e673512d3029eea3e933e56eb19a7f101a4f02d0d44cb96126a81909f2f11f273f29447035e756acb42d8a5bccc103385e66e38b9ac8c41e367f5b9089f56500b72f7e78c971b0ee5551a9fcef1ad8b421ea6fd96f0d19f7eefbff7de28ad34c066706a00cbc4f20979af353a1c12d8a8b65460527466ec5a109cce165984870ecac622c449d342c7121a28d74905e9029017ece042cc9b181f9672a143b7a3ba098fd7cc90003787e5d63c2ee0fcb4640ea09c0956127ab0f9a41fe339d44f00553f2bcd10f18bb3102095573dfa2e55bf7539d300b696b808231afe619347fd676d66b7d8fbb131285d40a199428dd1fe03d1c507fc3dab0c524a8b17512c476cb7da5ed297f081f3644cf1c20533c92bb54902f588bb6583aff5322000278c67b9fe65cf80ed5750b45d5622f87a0654f98f2fc867b2519efeb9834404e4cae41b052b7984b940d24e0b6718b00bb0f7c6941feff28297b1231a62a2104ceff7c8007aa06aad4b162db67f10ad626bdf8b6fc8c01d79e9f710307a847ad898e42d2c61113758de7e559df77f5b10062e599303dfc83064bbed865eb544443e1693e06ea710eee1aa43d3311d3c413569dfa2773b594
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134053);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3133");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66135");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-bypass-5Cdv2HMA");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (CSCvq66135)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by an input-validation flaw related to
the email message filtering feature that allows further attacks by
allowing malicious content to pass through the device.

Please see the included Cisco BID and Cisco Security Advisory for more
information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-bypass-5Cdv2HMA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1e5404f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq66135");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '12', 'fix_ver' : '12.5.0.031' }
];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvq66135',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
