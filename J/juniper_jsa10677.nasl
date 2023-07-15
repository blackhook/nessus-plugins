#TRUSTED 39a6c2750adb64c61e89ab988b846abd5afcd7d625a6ff188662b4b7617ae1a0c032cd044b6ae748c96a36a4d7344401d4c22793121cff8e73546480cec79ae917be2055d1e15fe0aa6e27c7f76e961e1f9fc890d9de18f1ac4cd4237213679044b4e37072d11173825a72e2d90ff7d5095e63da36847738ebfa6bc1585ae058e2adc3d3dd12340aa9767b70877cd66f84d30aff9e94ea97a49837e10626485dda4f3278f93428806f413642f903b5be9c54da7523fed4c3a0986af0e87b714f2f2e03a6398537224c8bc81aea90f3dd41a27cb87fc7416184cdd84d1d4d0bd6a0627215cf5bb15452089c92421c4ca778ffe140a48ef9ab06b47afc56caa6c8b23f006766617a5bcd8313492ef6f53413327ccbbb5a9b5e3c9f12058d4998a570592772a8177da139f344c178c871dd88fc0cf2ac1cc1647d65f4d08bcf51256fc589c033e3299bf1d95f362a13045a1ac038e5b8c1d441fe94bc0b04db0b3640cb567a5a37e7ad606166e07f36654e79afb126a147dec92ddcae5c1bf617634d239847a68ac722127312d9cbd91aa2117e5d13f8a304f9fb7c59188473e8ccc179929c0aa1bdfc470d5be22cb300fe304fb972bdde8165951dc1b324944f765ea7a4aaede9ae1048b1533f503ee341250ac00cbdea3847de13a2efd34ce9d4ce7bc7ffe449ea4162d31002148ce3b4a5b5018bfba0ae939a069c1558a29de3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82797);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-3005");
  script_bugtraq_id(74016);
  script_xref(name:"JSA", value:"JSA10677");

  script_name(english:"Juniper Junos SRX Series Dynamic VPN XSS (JSA10677)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a cross-site scripting
vulnerability due to a flaw in Dynamic VPN. A remote attacker can
exploit this to view sensitive information or session credentials.

Note that this issue only affects Junos devices with Dynamic VPN
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10677");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10677.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ('SRX' >!< model) audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3X48'] = '12.3X48-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Dynamic VPN must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set security ike gateway (\S+) dynamic "; # Check for dynamic attribute
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because Dynamic VPN is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
