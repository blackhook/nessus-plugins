#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128064);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2019-1714");
  script_bugtraq_id(108185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn72570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asaftd-saml-vpn");
  script_xref(name:"IAVA", value:"2019-A-0271-S");

  script_name(english:"Cisco Firepower Threat Defense (FTD) VPN SAML Authentication Bypass Vulnerability (cisco-sa-20190501-asaftd-saml-vpn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense (FTD) Software is affected by an authentication bypass
vulnerability in the implementation of Security Assertion Markup
Language (SAML) 2.0 Single Sign-On (SSO) for Clientless SSL VPN
(WebVPN) and AnyConnect Remote Access VPN. The vulnerability is due
to improper credential management when using NT LAN Manager (NTLM)
or basic authentication. An attacker could exploit this vulnerability
by opening a VPN session to an affected device after another VPN user
has successfully authenticated to the affected device via SAML SSO.
A successful exploit could allow the attacker to connect to secured
networks behind the affected device. (CVE-2019-1714)

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asaftd-saml-vpn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bb85a40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn72570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvn72570");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '6.2.1',  'fix_ver' : '6.2.3.12'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.3.0.3'}
];

var is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
var workarounds = [];
var cmds = [];
var extra = NULL;

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
  else
  {
    extra = 'Note that Nessus was unable to check for workarounds';
  }
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [WORKAROUND_CONFIG['show_webvpn_saml_idp'], WORKAROUND_CONFIG['saml_2_sp'], {'require_all_generic_workarounds':TRUE}];
  cmds = make_list('show webvpn saml idp', 'show running-config');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn72570',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
