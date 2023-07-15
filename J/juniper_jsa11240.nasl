#TRUSTED 8e85281a59e9e08e3af40662dff2e9fbce5639b018a1da07de07d22acaf904f721bfb3d932ef20cbcdb3f1f3ef03e2b59f6d65e0bd053f032f75cedf46014868bcfc83c9685a450f9c8cbcbe6683997f1113af669adc36ce6b49ac1c76460603fff7c6982c0b55b5247fad12cdb7f3b38b0ee8c753eb2c126b3cdb0fe656694b070c52bf8a62205dd8542e1e4afcacab1705f16b9a26d8a2d5c79f83c007c6f44d3d857773d32849e0438fd01fd0ca34041f3115cede9b4a8ca7fb2ed490e0be665ac6c7fa7036f1ed94101a71519c1194213c308be5302f041c569e9e3c38344ce51d1fc04202959e6fa6bb8b8711b593cfcd7ec213f677d84870f3542c502939a2de758bd65455339c92b07e2b79ff9c7e63d09f5e55e0ee503df8be3963e75336752fbb45cb940da9227875f41267ea6756bf45944b34670d7134d0d7493f1104499e60bb07a92b8aafda3d8f5b91df9e5a9dc3a7201522ab12ed17ed9dfad2079dd0c2d048295ba408b7ccba886e00285ddd23db535cfea9d51130077f64d8070ad15451586cda8ec34e89e136e36b51650a9f776c98ac451b7a456351163355a170cdef82fe1c8e032aef53256f489c8e7f116743692576689cd32413bc499e303460bb9005b6d38c76bf5a79d502c7c522d39b09dc96a6d5947eb961bc086f7eba12057aa4823342993ede9cb155b85f64d96a05dec94982599f43c166
#TRUST-RSA-SHA256 06f593a01e9c78a2140f36d455c3b7ad56d36b61120627cdedb52d6140a26b4f473742b68e3599340304796f45bfdf0a73ce5d59c65229a06435429b2ac673736a36df26884082a1529f116dda64b6597bf28fe1b3cc43b7595d5ee638b33d464f6be0b0ff5ec41f77b85943e45bb17e327d41262c0d3c1a5bf19fc5152bdf490a0ed29d9649306c91270ea3fd12d1a660fe1ff2d5c2ffe80450442a376d488c15aed0218672380ceac2ec523d7ba3c873a266adff304e39c1cdf8997f534a07d7cea7c5bb19e8363ceb5c1ee46e8eaaac12bbd03893f88990cc1074fedbbbdff4a0058449c5c1e625b223d03295042b0f2996324adf31b340dc5e96ed6e89e9dfb94c04cf67c4bf48120cad38e8c31d1a5d28827c79632f573ca8508882c61fda6a34e9757b4a558f06e21121f6c670d778184c9380b717d47bd1a3570f16b7ccd8beef9b680801b2382b2c2f6f314eba5f0fbb8f42c6c3e7375bf0d4eef20f6878639bbcb2b1dd4fa8a842f3989732a614362eb9f3a965cb180411fda1085f9acd6cf4fb74f6cf282cc9b7540665f96b7106da695b4ea7cf364c62e4704d6ad2f391f81da1b72ab957015ac5513de2ff8c1eead60401c67224ad96031de00dab2bfa9f5dbd7b24fa4dbb4df1f13907d556fd352f60cddd11bb83c8e2ca980b8d7a618a4bba6a234d7e0c89601343b93b2d536b90e77e1aca045d5c1efc4bf2

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2021-31375");
  script_xref(name:"IAVA", value:"2021-A-0478-S");
  script_xref(name:"JSA", value:"JSA11240");

  script_name(english:"Juniper Junos OS Spoofing (JSA11240)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11240
advisory.

  - An Improper Input Validation vulnerability in routing process daemon (RPD) of Juniper Networks Junos OS devices 
    configured with BGP origin validation using Resource Public Key Infrastructure (RPKI), allows an attacker to send a 
    specific BGP update which may cause RPKI policy-checks to be bypassed. This, in turn, may allow a spoofed 
    advertisement to be accepted or propagated. This issue affects: Juniper Networks Junos OS 12.3 versions prior to 
    12.3R12-S18; 15.1 versions prior to 15.1R7-S9; 17.2 versions prior to 17.2R3-S3; 17.3 versions prior to 17.3R3-S7; 
    17.4 versions prior to 17.4R2-S9, 17.4R3; 18.1 versions prior to 18.1R3-S13; 18.2 versions prior to 18.2R3-S3; 18.3 
    versions prior to 18.3R3-S1; 18.4 versions prior to 18.4R3; 19.1 versions prior to 19.1R2; 19.2 versions prior to 
    19.2R2; 19.3 versions prior to 19.3R2. (CVE-2021-31375)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11240");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11240");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S18'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S7'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9', 'fixed_display':'17.4R2-S9, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S3'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S1'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2'}
];

# BGP must be enabled
var override = TRUE;
var buf = junos_command_kb_item(cmd:'show bgp neighbor');
if (buf)
{
  override = FALSE;
  if (preg(string:buf, pattern:"BGP.* is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled");

# A BGP peering session is established.
# EX. Peer: 192.168.40.4+179 AS 17   Local: 192.168.6.5+56466 AS 17   
#     Type: Internal    State: Established    Flags: Sync
#     Last State: OpenConfirm   Last Event: RecvKeepAlive

  if (!preg(string:buf, pattern:"Peer:.*State: Established", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP peering session is not established");
}

# BGP Origin Validation is configured with RPKI.
override = TRUE;
var buf2 = junos_command_kb_item(cmd:'show configuration | display set');

if (buf2)
{
  override = FALSE;
  if (!junos_check_config(buf:buf2, pattern:"^set routing-options validation group .* session.*", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because BGP is not configured with RPKI');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);