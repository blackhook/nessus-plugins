#TRUSTED 91afa616d4a9898c1e5bd81bc57234ecb60969fb394ee54175866835e4a55fcd119743ac69a4be90882dcc63d972b061733a881d9a7db1f350ff629c8380d663d9bd1c0ed59a58ffcc22a580f0c638d590263f23c3519a5a81f65ac74ef6c53459f54f99bd5c43dc41a2c5725e591d1a7027b90b08c14eff91ea40a1535d31565b639fa83b17aa16955df28b54f0414812ca533bf3e75f9e65ed7c5a4d87afd0fdc4bcfa0cfaf14d1c78b1b208d5d8975a47ab0e9abd6430adc3fcb56d2df428d837b7f79a5465742ae8fd9b87f5ab141d27fa35c2c4a3e309819553e75d97d03c8f97d8e1c12fcadb19fa19c0be7c7f2386a8bfec7c29ae4cc9eda7a7b5c744bc12ddecf26c2380821684ff1ed65e8a1c8ae0377bc47dbdfc2d08b3a9ea6b4b169c5d793f8b54fb415697a509cb65294a45db77b697a5d4f8b9ddb613d7b6658ba858d861394cce7c8269f7e18b2e831a22748f2f2d69d5e296c4d051d07da929d76949fb3fbd30101ac5284ab5d6018e38a4c7ec26d02ab83a1f44fc7df0b3e12a95a0a4b16706efb04176e1a740360b8e387b95a290a90fdea21a1f31c51c66d5d3ff190651fda8f65d6a77145ab5868d22b0a5e6a4c189b99a52dc3186fdd9582f6aeef5f592fbf050274e747761d1c225505f785f63bd332432a1ffa7445800fa777cb7ee9089fa835d6b6bb3c16915e4bfdad7c30770e94f78494562cc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118461);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id(
    "CVE-2018-0417",
    "CVE-2018-0441",
    "CVE-2018-0442",
    "CVE-2018-0443"
  );
  script_bugtraq_id(
    105664,
    105667,
    105680,
    105686
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf66680");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh65876");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve64652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf66696");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-capwap-memory-leak");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-gui-privesc");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-ap-ft-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-capwap-dos");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN
Controller (WLC) is affected by the following vulnerabilities:

  - A privilege escalation vulnerability due to improper parsing
    of a specific TACACS attribute. A remote attacker,
    authenticating to TACACs via the GUI, could create a local
    account with administrative privileges. (CVE-2018-0417)

  - A denial of service vulnerability due to flaws with specific
    timer mechanisms. A remote attacker could potentially cause
    the timer to crash resulting in a DoS condition.
    (CVE-2018-0441)

  - An information disclosure vulnerability due to insufficient
    checks when handling Control and Provisioning of Wireless
    Access Point keepalive requests. A remote attacker, with a
    specially crafted CAPWAP keepalive packet, could potentially
    read the devices memory. (CVE-2018-0442)

  - A denial of service vulnerability due to improper validation
    of CAPWAP discovery request packets. A remote attacker could
    potentially disconnect associated APs, resulting in a DoS
    condition. (CVE-2018-0443)

Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-capwap-memory-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e14b610");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-capwap-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d106cd6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-gui-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4eb02b4");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-ap-ft-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9605ddd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf66680");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf66696");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh65876");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve64652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf66680, CSCvh65876, CSCve64652, and CSCvf66696.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0442");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.140.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.131.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.7.102.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf66680, CSCvh65876, CSCve64652, and CSCvf66696"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
