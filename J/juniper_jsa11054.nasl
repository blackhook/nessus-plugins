#TRUSTED 54e06d7b29302b4b508d68eb08950fb07df7473a9db7b204591c43925809b8953f9d26ab6c731d9cf9b699fcfebfc594d31ee4bdb6d1dc738dc722606a12a85724d582d232587d0e4d448c64645c7c8f122302bad4764f517d905aa7a3f30ff23ff51766cde14bfe52f1342ae2267f0997ddc6e1914fd5006835c8bbbc5eda3b778e968af0051d2a03dcca039652c8923b8fa45dac9566f9cd43add7bffe0f3bc0f0aab38d330e67be75b3eb62494b97e404d513ad08433367367c8333065ed65e8bc81d917013d2bb4976ca7482fbf8783e90a8d9af4cd57511393301f0c1653c77870c12876cd8bdf448343f5ffa61002e4b5a2b5654d4702f77b71acb1ecae0950de71a968f5f64ddf4b2bed495b8c68350848ddefbd16efbbde307fb9c01fe6470a3f5e5f81a1eb7408c7f9442128d6d90fb6d5931c0410638a197a35053c49ee30dbfe4dd77e30766d47fd125a3243d0d05fe4c9755dc8a11ee8a1b926b122b5a283a71653c0fe986b0171372506f4c03034696991dab1e1f1a32cee3c6ef4178669226632314d516a87ee147f213593d22a58e9bdd08c4941617004ab8b552599cad68c1663a3885a9996b918021bc603c964d8eac0b7fe9d9bd8bd17b935e700d8205fa6a0355b1bb37690086c9f5adcc7f797db16f9d021a6e11e59ce37b62d30e6c5f6b0be0a591284eeb5811d2ec93954e5c121d9c8f6c428f5245
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151625);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/19");

  script_cve_id("CVE-2020-1660");
  script_xref(name:"JSA", value:"JSA11054");
  script_xref(name:"IAVA", value:"2020-A-0467-S");

  script_name(english:"Juniper Junos OS DoS (JSA11054)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11054 advisory. When DNS filtering is enabled on Juniper Networks Junos MX Series with one of the following cards
MS-PIC, MS-MIC or MS-MPC, an incoming stream of packets processed by the Multiservices PIC Management Daemon (mspmand)
process, responsible for managing 'URL Filtering service', may crash, causing the Services PIC to restart. While the
Services PIC is restarting, all PIC services including DNS filtering service (DNS sink holing) will be bypassed until
the Services PIC completes its boot process. This vulnerability might allow an attacker to cause an extended Denial of
Service (DoS) attack against the device and to cause clients to be vulnerable to DNS based attacks by malicious DNS
servers when they send DNS requests through the device. As a result, devices which were once protected by the DNS
Filtering service are no longer protected and at risk of exploitation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11054");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11054");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S1'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var vuln_cards = make_list(
    'MS-PIC',
    'MS-MIC',
    'MS-MPC'
);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show chassis hardware models');
var vuln = FALSE;
if (junos_check_result(buf))
{
  override = FALSE;

  foreach var vuln_card (vuln_cards)
  {
    if (vuln_card >< buf)
    {
      vuln = TRUE;
      break;
    }
  }
  if(!vuln)
    audit(AUDIT_HOST_NOT, 'using an affected line card');
}

buf = junos_command_kb_item(cmd:'show configuration | display set');
if (junos_check_result(buf))
{
  if (!(junos_check_config(buf:buf, pattern:"^set services web-filter profile .+ dns-filter-template ")))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');

}
else
{
  override = TRUE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
