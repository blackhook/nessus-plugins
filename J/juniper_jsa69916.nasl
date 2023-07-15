#TRUSTED 78cce2527e0c8a465b80310aeb25137b50a25b7838fa77721b0b2db4ecbbd6d76699517d78b9ea927948f58bcb4a7167020d4f2f5f33f7f3ba3a3fc6e9e6ef21d35efee43cc6a76681c8606cd764540044eb9a0021a50fd32038c39c71f20d2990884be2a3265b3552946449c90d9c970ffcd9cb53e86d724c238fd0f520f6195b899da128074ad32d41f797ede851109464a82165d7199deadc0e966ed04250509fff04faf4455614c327bb22a53c336a8b67dbfb34547d59febacadd2559cad9149621892cc662f5a3adb3deac4d528d8996b7939b5994534af85e8414f008687d4b61ff40acf707dac3f86178548f6ee878bacae86d3681dfdba9a035cf9f7451a9c55fc0c110103e24881f2d51ac40d7d2b98179836805ae1f7c99bd425ceceb9e4b95eaae50f12898e4e5b8d79bc081ea0035c391bb4fca3c8124606080148ecc9a17556c8117f67dd5bde3b89aa5734a6d2479c97fa74fdfd4054819df0de30a2cb6f4b71a2d9f0dc9e0c074f5415bb45d1a316ebd6d56f3b6b641c4abd7e02b98dff315cd306b70bdd00da767cb7a111401b06d6e2076b840b633dc7ce3899368f2664cdce49995fa69196efef42a126d562f7e8b61d646d9b6e16f0a1c52bc066a3be7eccf5e0d938b874b342ca38de6e25a8a3bccf9c2f1fe667079d7b43d128983df27fa180fcbaf3829a9bda610f8bbf5bcf540b88d21f3359f52
#TRUST-RSA-SHA256 0b72dd9356686cd3ad2c8973a21349d8e5aba9231abaf11b795681bd0c8142d6f6ed14ee922ff4a06209a457814c2b81cc4ae8810e9d537edd586832df72d2ad8f32711b70155e0e4bdce45432d8993b0720d43dd348d5b990c32631c195289d915f42c3c99deac2e8d29b94ac43986f265608e7c9093a8194c5b190de915d7bd5bd9b1c69e837bdc4c7140eb3a42a4a1d2faa7082e16a380803c3863debcc6108d108cff882da60908ad5225d4df875d8da81107e3e153fd74a6586dab73323f6243d2de4cad67451dc0befbd0523cd488fb930f24059854c09a9bb2a4adfb17d88cd02a388722ad8d7529b2a28a91ae45ef418d9e698afa0ac9abd9a2e18fec2657188d20125afd868737c1808f184e37c2eb727dd013f8a0351ebbbd3e2b7f84a6394f939c5b066a42c40cc44906eb7f3cec19d7f6194368f41a7cc4e3fbce72a7c1db5794c752944db5d4e1e04369522b3ba9b3db81a39489f461c8c531f1fe8edd20a20482ade42827953877a7b411878ddf9cc5bcb1dda6d4b48051c6e465b5dfa3eacafc6f5f58adc565c46b5afbc5170b5e255826ee447e1f57f4eea199c6f06ff0f13cb0138126f8130b272297ee92c3c6f915f6ada5df5f187c68b1351c3c06f9d4607e9e87945f0a23cf840ab7fb535284453f41b986df70aa2d3fe9fb02cd6d32e94dfe4c77d3f0d3b97498c735801c4716696660766048966d3
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166459);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-22211");
  script_xref(name:"JSA", value:"JSA69916");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS DoS (JSA69916)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69916
advisory. A limitless resource allocation vulnerability in FPC resources of Juniper Networks Junos OS Evolved on PTX
Series allows an unprivileged attacker to cause a Denial of Service (DoS). 

Workarounds are available as referenced in the JSA69916 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://juniper.lightning.force.com/articles/Knowledge/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00a9cacd");
  # https://juniper.lightning.force.com/articles/Knowledge/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812ee185");
  # https://juniper.lightning.force.com/articles/Knowledge/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0ab70e2");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-PTX-Series-Multiple-FPCs-become-unreachable-due-to-continuous-polling-of-specific-SNMP-OID-CVE-2022-22211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd773fd4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69916");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ '^PTX')
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'20.4R3-S4-EVO'},
  {'min_ver':'21.1R1-EVO', 'fixed_ver':'21.3R3-EVO', 'fixed_display':'21.3R3-EVO, 21.4R2-EVO, 22.1R2-EVO'},
  {'min_ver':'21.2R1-EVO', 'fixed_ver':'21.3R3-EVO', 'fixed_display':'21.3R3-EVO, 21.4R2-EVO, 22.1R2-EVO'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-EVO'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R2-EVO'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R2-EVO'},
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set event-options event-script file .* source .* refresh", multiline:TRUE) &&
      !preg(string:buf, pattern:"^set system scripts (commit|event|extension-service|op|snmp) file .* refresh-from", multiline:TRUE) &&
      !preg(string:buf, pattern:"snmp", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);