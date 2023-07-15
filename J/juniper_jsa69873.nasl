#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166604);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-22223");
  script_xref(name:"JSA", value:"JSA69873");

  script_name(english:"Juniper Junos OS DoS (JSA69873)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service (DoS) vulnerability. On 
QFX10000 Series devices using Juniper Networks Junos OS when configured as transit IP/MPLS penultimate hop popping 
(PHP) nodes with link aggregation group (LAG) interfaces, an Improper Validation of Specified Index, Position, or 
Offset in Input weakness allows an attacker sending certain IP packets to cause multiple interfaces in the LAG to 
detach causing a Denial of Service (DoS) condition as referenced in theJSA69873 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69873");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69873");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX1")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S8'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S1'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^interfaces .+ unit .+ family inet address", multiline:TRUE) ||
     !preg(string:buf, pattern:"^interfaces .+ unit .+ family mpls", multiline:TRUE) ||
     !preg(string:buf, pattern:"^protocols rsvp interface .+(\\n|$)", multiline:TRUE) ||
     !preg(string:buf, pattern:"^protocols mpls interface .+(\\n|$)", multiline:TRUE) ||
     !preg(string:buf, pattern:"^protocols ospf area .* interface .+(\\n|$)", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
