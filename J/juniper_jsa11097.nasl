##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145691);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id("CVE-2021-0207");
  script_xref(name:"JSA", value:"JSA11097");
  script_xref(name:"IAVA", value:"2021-A-0036-S");

  script_name(english:"Juniper Junos OS DoS (JSA11097)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An improper interpretation conflict of certain data between certain software components within the Juniper Networks
Junos OS devices does not allow certain traffic to pass through the device upon receipt from an ingress interface
filtering certain specific types of traffic which is then being redirected to an egress interface on a different
VLAN. This causes a Denial of Service (DoS) to those clients sending these particular types of traffic. Such
traffic being sent by a client may appear genuine, but is non-standard in nature and should be considered as
potentially malicious, and can be targeted to the device, or destined through it for the issue to occur.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11097");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11097");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include('junos.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX23|EX34|EX43|EX46|NFX250|NFX350|QFX5)")
  audit(AUDIT_DEVICE_NOT_VULN, model);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S7', 'model':'^(EX46|NFX250|QFX5)'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S11', 'model':'^(EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 17.4R2-S11, 17.4R3-S3 or later'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S3', 'model':'^(EX46|NFX250|QFX5)'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S9', 'model':'^(NFX250|QFX5K|EX23|EX34|EX46)'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S3', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S1', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S5', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 18.4R1-S5, 18.4R2-S3, 18.4R3 or later'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S3', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 18.4R2-S3, 18.4R3 or later'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S5', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 19.1R1-S5, 19.1R2-S1, 19.1R3 or later'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S1', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 19.1R2-S1, 19.1R3 or later'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 19.2R1-S5, 19.2R2 or later'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S3', 'model':'^(EX23|EX34|EX43|EX46|NFX250|QFX5)', 'fixed_display':'Upgrade to 19.3R2-S3, 19.3R3 or later'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S2', 'model':'^(EX23|EX34|EX43|EX46|NFX250|NFX350|QFX5)', 'fixed_display':'Upgrade to 19.4R1-S2, 19.4R2 or later'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
