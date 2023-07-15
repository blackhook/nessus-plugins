#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156689);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2022-22153");
  script_xref(name:"JSA", value:"JSA11261");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11261)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11261
advisory.

  - An Insufficient Algorithmic Complexity combined with an Allocation of Resources Without Limits or
    Throttling vulnerability in the flow processing daemon (flowd) of Juniper Networks Junos OS on SRX Series
    and MX Series with SPC3 allows an unauthenticated network attacker to cause latency in transit packet
    processing and even packet loss. If transit traffic includes a significant percentage (> 5%) of fragmented
    packets which need to be reassembled, high latency or packet drops might be observed. This issue affects
    Juniper Networks Junos OS on SRX Series, MX Series with SPC3: All versions prior to 18.2R3; 18.3 versions
    prior to 18.3R3; 18.4 versions prior to 18.4R2-S9, 18.4R3; 19.1 versions prior to 19.1R2; 19.2 versions
    prior to 19.2R1-S1, 19.2R2. (CVE-2022-22153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11261");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11261");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

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

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(MX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.3', 'fixed_ver':'18.3R3', 'model':'^(MX|SRX)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9', 'model':'^(MX|SRX)', 'fixed_display':'18.4R2-S9, 18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2', 'model':'^(MX|SRX)'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S1', 'model':'^(MX|SRX)', 'fixed_display':'19.2R1-S1, 19.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
