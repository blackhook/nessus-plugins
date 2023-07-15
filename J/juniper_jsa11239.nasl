#TRUSTED 91f4a00bf68efa98882b662195f64134048de368cb1543f38444bc9c99cb4529789620c1892cb1d994ebde5dcaaf9b23b49675aa67c8e6bd78f57d3e0139e059d5ba25fc8a428b3335ddc0d1cf0c1a0f3ad515ebfc11568cdb27fe30f095b7d90c1ab3707d6eab501efd7f62aa01607ba16cc81a18ef5ad97251638d96d0200dbd3e27206620aab0db41b8b61d772129f4d8657d7a9e488a7e5588b0596a6725d5af1705c2b4f8945a6a002f437637ca9edf120e8fbb0e53b81106e4a102945abe0f78876d049079fac30dc9d238fea4cd5319758d5c8ecdd603f72ced8c601a19252969a37cad6f236f1dfbdd9dd59cae374b158cb38eab0f510edca2aef51a8ee84e3ed19753656db3795f501104f62ac3f292840daca5ae286c67138ec85389e8492c17e50fdef2f4fef42b94233fdb613136efef738ea65e0678df36bf27d857c61b0f779280e03983c6fbf7990c510248759f02e89fc9329f7701b8c6405809ad02970e2a1db3e29b0216a142342ed29d9118bd6339030c1e3371d671706c35f607e49b3dea4fc50e2098218e4e60ecc302ffa444f63ef90ef7f9fab507b5bb3da73c01120d3f630d6f088c0a1b038f646890560e9e6e93bc3d4a939eb7c7444f397577a22b9ec3cd6e35e0c181c08134f6e4717540666a82d4a0de185bbdc6958b2740e906d1ed79d0f577a4ab70ce39dc814b2b1baf8e9ecb85089893
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159280);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2021-31374");
  script_xref(name:"JSA", value:"JSA11239");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS DoS (JSA11239)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11239
advisory. On Juniper Networks Junos OS and Junos OS Evolved devices processing a specially crafted BGP UPDATE or
KEEPALIVE message can lead to a routing process daemon (RPD) crash and restart, causing a Denial of Service (DoS). 
Continued receipt and processing of this message will create a sustained Denial of Service (DoS) condition. This 
issue affects both IBGP and EBGP deployments over IPv4 or IPv6. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11239");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11239");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

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
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S4'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S7'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S7'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S7'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S3'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S1'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1', 'fixed_display': '20.3R1-S1, 20.3R2'}
];

# BGP must be enabled
override = TRUE;
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

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);