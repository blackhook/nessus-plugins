#TRUSTED 9242bc45c14fe3c112e43beb15e5baa22dd6d0402e8125c248c67066f5c61fbb4a0128d51a5b0fcffe6c11d0a872c57734a7c140698d724ca06d06365f2b5ffb07ce12161c11a044cae2c5bdddc9dc6b6cf23848446e67e1bfd4c24d4253a8ebd3c4b871f524f4ad5ebcb29e581cc562d0b521b517dd167229ede49b5ead5ca9256083931d0468cd33790decb35ff00493a004eaa26a457da51805112d100515264924d1b9b8cb006e80b50723c4af94530e0e358a96fff556bc0eb092b1b2dbc6c631cf023a330958d1f4d6c91139927c95d63eacbe971376d918e57beed74ca09de3cb2cc253e57a48104a72ba76b12a31bd0fc9628a7858f09b786ed031c32ae4add033a5bd541b2f6e42509ae0a38aaef6df965375ae7cb33fec3e639348415f242f443419c9bfa0edaf28e8b737ff0d65ff86204d1022000a47405df018e7a35f974e5bc317c12e9900aa5ff5aec138ab5f2e6ce9ad434228a6f9b415a65cc1fb61c3c8393b01accd8329c9bba505e2a570206ea63d8736b4179be6834227bc5c0a3ebc8ff95b274f3e282fa4f4e546173ee24797a321b50b038255e238899271fa2efabae73dbd005d6562ce6c81750fc72abc687c8463e9df9b9c535ea2bc5298f0c1c8885dffa972ad40b4f5f719829e6a92d923ab2e99e4d7fba8a8fc2841871e2de69a1e4c7bbc64bc9fbe0c5134a60c1756ef44d27b4395bc1647
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133725);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/23");

  script_cve_id("CVE-2020-1604");
  script_xref(name:"JSA", value:"JSA10983");
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Juniper Stateless IP Firewall Bypass Vulnerability (JSA10983)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self reported version, Junos OS is affected by a vulnerability in its IP firewall
filter component. A remote, unauthenticated attacker could exploit this, by sending specially crafted
IPv4 or IPV6 packets to an affected host, to bypass firewall restrictions which have been put in place
by an administrator.

Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10983");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10983");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();


if (model =~ "^QFX51[0-9]{2}$" || model =~ "^EX46[0-9]{2}$")
    fixes['14.1X53'] = '14.1X53-D12';

if (model =~ "^QFX35[0-9]{2}$")
    fixes['14.1X53'] = '14.1X53-D52';

if (model =~ "^EX43[0-9]{2}$")
{
    fixes['14.1X53'] = '14.1X53-D48';
    fixes['15.1']   = '15.1R7-S3';
    fixes['16.1']    = '16.1R7';
    fixes['17.1']    = '17.1R3';
    fixes['17.2']    = '17.2R3';
    fixes['17.3']    = '17.3R2-S5';
    fixes['17.4']    = '17.4R2';
    fixes['18.1']    = '18.1R3';
    fixes['18.2']    = '18.2R2';
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for stateless IPv4 or IPv6 firewall, if not output not vuln
buf = junos_command_kb_item(cmd:'show firewall');
if (junos_check_result(buf) && buf =~ "family inet")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
