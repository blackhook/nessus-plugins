#TRUSTED a9c7536cac0895f08de09eca294e0feda3328a62c37b16262ff8da2ad3f5b7d4df2821d3d868cd4408562c87852cbe49106bb96a95deea9d7d81fe478f20cccbc4de6436d8afc96ffe6a31549a192c393dc61b03bcd04b165b672d31692a597c243b96818ca3ee18d819dc1b7780f4943d8187931e3a8ce10322f4cea1b1759c9c1043d66d9dc25a55f9971e3832c1459ac99e865243330f6a970eae2c18adf43e2755743ec85bc79d86d281767322f306cec58208f2d243cbab0a7bf63173e5e1b231fdd42b355899f07f0197330788158fc759f4f8abdba419f7cf8c474cbe028f22577cedb639373b9933fd6a846942feca68656918958e7b085058349562aea4dd90581b09e9d70586bc38b13abf5aa7460036fcdc7089f43054a1c0bec8305483e1501b73a937ced58921a87968a52202bae296565e0fa1591f79fe01302ceb758e3f49c42b22b82af54d06882613d0427c22bd3d99b286351fa95819305dc3467c7d925a4685ab6632e44ec0ab4075f998ddf72e5cb41dc5a3ec07457c4e5930063ce76840e2f0b6b7f921cdad77ea86d62f32c46835e102659a3d6a8fa732bbb6bd3636b5e6711c047c3f94da279f32cb8ce0dcfbf1dbe0a721227143c87dabc4bee106ad418061d0d3856073d955c12ab527461f327636081bc0de9f8bbb1e2bef9d28232250ae25a3bdf8c8bc9aa11aaeedda61a94352d080a66a62
#TRUST-RSA-SHA256 89e32d01fcf3ac28e4f397f40d0f371d010a3a69e47ef7c64a0fd9f3f039547144bb9cc4c3a3efa48b481eea73cc7a6f16276a6099a396a375f94d086695b9e0576deb1bb2169d10d7d56bffd9dc188893a3fe5e4b9977bd0210c0cbbd4726b7ff92154854fd00c92c9f70aa4db2a28841ccc372c35e0b6b7f42994ac301a0195dfc25acf0c11ae59b938eea58b2656441e049d48f2ef1384487f02f88aaa0e5532dc5729a81821a56e78023a7ea4b5175d13ed836543670b0cc38ca997055c4dc5b13457d83d5323eb8718f600ea204dc6a63529cc5c681ea0ddce5e44306041bac0980f1fd75fbb432f60ea160e788a24a0f024a15bc9c92d16d18b44ffc600e546c85b8e91ed8e8c8b291d6f9209da0fd7860b2f1071ae26c826d6370dc3b2f2abf8553a5e571baaa1926b076932f14393a56667b7a67084e1fe61a6346a47e7758a4a1c7065fd8b2bb7daec9e4a2860b309e111e8ddb299a931cd77f11b309b2a6ba8311cd46eea82fddb9a0a958e0f8e186662d7a5ac4b702a1aef6bf5faeb103529a10c67703da4d6b7a217a4b0977a1782d85b407965ed8431ffebf5022a7f0bdc3ba7350294647c4349a9e9cabfd934780d6f4dbc2185fd985ea1160710ddaf91e19e1049dfb83cc88824b3c1158bdd0d159d07e631db2f1747408de84d06e64eefe19f925c7022a13dc4ad152df4ffda7e9613ba3a541f478a614ff
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177837);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2023-0026");
  script_xref(name:"JSA", value:"JSA71542");
  script_xref(name:"IAVA", value:"2023-A-0318");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71542)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71542
advisory. An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS 
and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). When a BGP 
update message is received over an established BGP session, and that message contains a specific, optional transitive 
attribute, this session will be torn down with an update message error. This issue cannot propagate beyond an affected 
system as the processing error occurs as soon as the update is received. This issue is exploitable remotely as the 
respective attribute can propagate through unaffected systems and intermediate AS (if any). Continuous receipt of a BGP 
update containing this attribute will create a sustained Denial of Service (DoS) condition. Some customers have 
experienced these BGP session flaps which prompted Juniper SIRT to release this advisory out of cycle before fixed 
releases are widely available as there is an effective workaround. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-06-Out-of-Cycle-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-A-BGP-session-will-flap-upon-receipt-of-a-specific-optional-transitive-attribute-CVE-2023-0026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be3e1b7c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71542");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'15.1R1', 'fixed_ver':'20.4R3-S8', 'fixed_display':'20.4R3-S8'},
  {'min_ver':'21.1R1', 'fixed_ver':'21.2R3-S6', 'fixed_display':'21.2R3-S6'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'fixed_display':'21.3R3-S5'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4', 'fixed_display':'21.4R3-S4'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4', 'fixed_display':'22.1R3-S4'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2', 'fixed_display':'22.2R3-S2'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'fixed_display':'22.3R2-S2'},
  {'min_ver':'22.3R3', 'fixed_ver':'22.3R3-S1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'fixed_display':'22.4R2-S1, 22.4R3'},
  {'min_ver':'22.4R3', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.1', 'fixed_ver':'23.1R1-S1', 'fixed_display':'23.1R1-S1, 23.1R2'},
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S8-EVO'},
  {'min_ver':'21.1R1', 'fixed_ver':'21.2R3-S6-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S4-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S4-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S2-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2-EVO'},
  {'min_ver':'22.3R3', 'fixed_ver':'22.3R2-S2-EVO', 'fixed_display':'22.3R2-S2-EVO, 22.3R3-S1-EVO'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1-EVO', 'fixed_display':'22.4R2-S1-EVO, 22.4R3-EVO'},
  {'min_ver':'22.4R3', 'fixed_ver':'22.4R3-EVO'},
  {'min_ver':'23.1', 'fixed_ver':'23.1R1-S1-EVO', 'fixed_display':'23.1R1-S1-EVO, 23.1R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols bgp bgp-error-tolerance*";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because the 'bgp-error-tolerance' feature is enabled");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
