#TRUSTED 76fe60aac24c6c17df7dd492afa31671154b5da4569c187ebaf9d1c2c35820c561f995988cff9143247f3697fb409b48cfdde02b0b023fd974b42dcd785a04072446d1069274dd919458991b4fd386e6e5fad9143ebcf340c9ffa7f8d586b9ee891d05a101b5220c1db45690570e43a73ea169e16127f3558d78da997bb6d1e4328cd164ba7ea5413a734b063906bae8986f3f7f1bccb4b5c3b267827cdf0943e77a0f7b4a2c81c3ff79c41d25cd30435c831d8db5a9714f5b6cafac36ea03953918f39b25bfa2d96e906a51fdf64f0b3c6a03757b93e5ff5c1339c065cc01a51b132088271f3cc4cb72588298727c55b76d77bfd50b5719c98605ad6de0f3643583785e2d71b9bb1f9c5d59df08bdb085ecdfed2c02fd23a841e80b6697b821be5c4b104673380c93ff79994e63b32af4bbbdd556161b94f1bd360335fba249a6a78e462dad56c8815ff3510870372e0bde61f73b1badee8c6c66e7c8f39ca29f5de348a35442d548c1210617cba901f261ceb5e0ef97a9c810b1f67529dbef4db9333fe99dfe9ddce4725e869a7c6499ebb8288bef0f715993fb04123d0d2282dd0bf52b26b11c8b80f11c6d2945f07d5af317003278a9fe4dda685426e9486c9b0e81f75f4b403d8a1c0e870fa3afedd8280b6d9361ba0872f00a0bf729723becc9824df6b6d1d2b38cd7c2602571049cbafc9d3b7f2f52023d884ff42a8c
#TRUST-RSA-SHA256 482044cf67dd410020becd3635aa7dc495d86c0233879d72c0f5370054d9f3a2f6511567b9d8fb072474e827ac7d0f7d2ca1aa119d18e13bfa401bdfe9c05f1567300b62958ee1f18ec44e8d20896f80c55bd9c7eb9da6d34693e6c0b0153c5e5004b158eb2650116cd6cdac0152b76fe6985da1aa2195825e442b576327d0186ee5877d014bdea8af0118030bcee77263aac8c1522780adfeb2e027e3508ff252fb3c6c4337a703fae7f076e404cc2f7a1ad5677f046403a52369cd337577fed369b27f2d0b6be87f2b20f67720782180d24f2f1e8eb2cfa726fe9cccb3d6780df2d242ad68490c9598d7f48d1f0181f4c457e6d6e38307c96817084b0a37ac4a28538c16dee811e29a06dec7d7141b3e959480e7cc037817a1309593314abb7fb76d696376ecefb34b577f8fac7a59f68ac379bbcb1b169079ac18ed17c056bf595ce072109139bcb655088abfd92a5a9bc8ed953cfd2f37423684381b67914cf56ad388c00a052d4a6efd5358bcc709fc3bdb1506727d0d973ea18fba41b04039b67335009b1141b1c417b1d8e1ff8899d272a3ade314df2793bcd707d4a70ff27a1b01e20db923d999407bd9d577e637cb100224279a4625f33d7c5a4c0bc1081ba7945d72705718fe19719544bae0985c07bfc27d4df1c0d9e94b43611d3409e5843c54da27b797f7a0b7373be55eaa2e3c9a73f288ed9d86616e10e9dd
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163404);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id(
    "CVE-2022-20873",
    "CVE-2022-20874",
    "CVE-2022-20875",
    "CVE-2022-20876",
    "CVE-2022-20877",
    "CVE-2022-20878",
    "CVE-2022-20879",
    "CVE-2022-20880",
    "CVE-2022-20881",
    "CVE-2022-20882",
    "CVE-2022-20883",
    "CVE-2022-20884",
    "CVE-2022-20885",
    "CVE-2022-20886",
    "CVE-2022-20887",
    "CVE-2022-20888",
    "CVE-2022-20889",
    "CVE-2022-20890",
    "CVE-2022-20891",
    "CVE-2022-20892",
    "CVE-2022-20893",
    "CVE-2022-20894",
    "CVE-2022-20895",
    "CVE-2022-20896",
    "CVE-2022-20897",
    "CVE-2022-20898",
    "CVE-2022-20899",
    "CVE-2022-20900",
    "CVE-2022-20901",
    "CVE-2022-20902",
    "CVE-2022-20903",
    "CVE-2022-20904",
    "CVE-2022-20910",
    "CVE-2022-20911",
    "CVE-2022-20912"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26499");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26501");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc26504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv-rce-overflow-ygHByAK");
  script_xref(name:"IAVA", value:"2022-A-0292");

  script_name(english:"Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers Multiple Vulnerabilities (cisco-sa-sb-rv-rce-overflow-ygHByAK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is unsupported and is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV110W, RV130, RV130W, and
RV215W Routers could allow an authenticated, remote attacker to execute arbitrary code on an affected device or cause
the device to restart unexpectedly, resulting in a denial of service (DoS) condition. These vulnerabilities are due to
insufficient validation of user fields within incoming HTTP packets. An attacker could exploit these vulnerabilities by
sending a crafted request to the web-based management interface. A successful exploit could allow the attacker to
execute arbitrary commands on an affected device with root-level privileges or to cause the device to restart
unexpectedly, resulting in a DoS condition. To exploit these vulnerabilities, an attacker would need to have valid
Administrator credentials on the affected device. Cisco has not released software updates that address these
vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv-rce-overflow-ygHByAK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?757478c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26220");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26221");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26222");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26499");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26501");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc26504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Cisco Small Business RV series router that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77, 120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:small_business_rv_router_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:small_business_rv_router");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

# Model example: RV130W Wireless-N VPN Firewall
var model = product_info['model'];

if (model !~ "^RV(110W|130W?|215W)( |$)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var extra = 'The Cisco Small Business ' + model + ' is no longer supported.';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc26220, CSCwc26221, CSCwc26222, CSCwc26499, CSCwc26501, CSCwc26504',
  'extra'         , extra,
  'disable_caveat', TRUE
);

cisco::security_report_cisco_v2(
  reporting:reporting
);
