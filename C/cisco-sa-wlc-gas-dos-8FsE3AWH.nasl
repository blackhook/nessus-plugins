#TRUSTED af1d7f2eeb088ddcd554ab8701caf6110d3a856beaba2ed1c25c7edc4b58da2d7cee66808f878400e5f211af859ececfa3cca2f490e96f52f0ea13d9fca99cef1a999b70d898dcd361b7f90c294e9ae3b1320c5e262fc490d0f0a5a130a41140e4aea53f8b58e11fc7396914272ad6a0e4a801feff8fb261b603ba746c01590c6c39e50a563fa1bc5cbecc8e7450c1d8932b9dfcb51d7b39825a77d9c12a7e04564f9d2bf7182b18dd20a2b764e6106ebca97d50927ea4c144e6b3dc0222dcd49c43449043d43119a64726fd16eddd5a651485e762d1a8bd0c3c604147e2dfebdc20d0ec9f130c17f5661e316c16cbf04835886ae4b0ee42172219ad423532e8147a72d3efcadab6b6980d51ed4cb6e0ae9bad3a0fee483594803e42b84d9217306714f29604fafd307d56f428ac011e31e0c1628e73e7160de050aa96223c2453aaf5e0824ee569a7a5b89686f9d91d8d79c32fba5c625b979476fc670e689825841aba2cf89ef2dd855b6e2d2cc6433c8c2690d6da4c839e122ef2763c6944a1d3bd904ea8edba73922152b3793099d7073fd6f57dc8a11fbc6224a62499d86262f045098da44b2e2a1bc921c789ce1fa4dfbb4bc87c3d07c57c3c80438631ad8f9248c7e2e62a01b6673f128365b2075e7391837e1c6e738a3117acaca6131366ce9c74d189869b138299fc2c511047b90b663d560515e9e28c84685771de
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135858);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr52059");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-gas-dos-8FsE3AWH");
  script_xref(name:"IAVA", value:"2019-A-0424");

  script_name(english:"Cisco Wireless LAN Controller 802.11 Generic Advertisement Service Denial of Service Vulnerability (cisco-sa-wlc-gas-dos-8FsE3AWH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the 802.11 Generic Advertisement Service (GAS) frame processing
function of Cisco Wireless LAN Controller (WLC) Software due to incomplete input validation of the 802.11 GAS frames that
are processed by an affected device. An unauthenticated, remote attacker can exploit this issue by sending a crafted
802.11 GAS frame over the air to an access point (AP), and that frame would then be relayed to the affected WLC. Also, an
attacker with Layer 3 connectivity to the WLC could exploit this vulnerability by sending a malicious 802.11 GAS payload in
a Control and Provisioning of Wireless Access Points (CAPWAP) packet to the device. The described attacks would cause the
device to reload resulting in a Denial of Service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-gas-dos-8FsE3AWH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b296684");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73978");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr52059");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr52059");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3273");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '8.5.160.0'},
  {'min_ver' : '8.9', 'fix_ver' : '8.10.112.0'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvr52059',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
