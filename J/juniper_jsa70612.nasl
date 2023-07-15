#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177112);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/12");

  script_cve_id("CVE-2023-1697");
  script_xref(name:"JSA", value:"JSA70612");

  script_name(english:"Juniper Junos OS Vulnerability (JSA70612)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA70612
advisory.

  - An Improper Handling of Missing Values vulnerability in the Packet Forwarding Engine (PFE) of Juniper
    Networks Junos OS allows an adjacent, unauthenticated attacker to cause a dcpfe process core and thereby a
    Denial of Service (DoS). Continued receipt of these specific frames will cause a sustained Denial of
    Service condition. This issue occurs when a specific malformed ethernet frame is received. This issue
    affects Juniper Networks Junos OS on QFX10000 Series, PTX1000 Series Series: All versions prior to
    19.4R3-S10; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior
    to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to
    21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S1; 22.1 versions prior to
    22.1R2-S1, 22.1R3; 22.2 versions prior to 22.2R1-S2, 22.2R2. (CVE-2023-1697)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-QFX10000-Series-PTX1000-Series-The-dcpfe-process-will-crash-when-a-malformed-ethernet-frame-is-received-CVE-2023-1697
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fdf7582");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70612");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(PTX1|QFX1)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.1', 'fixed_ver':'20.1R1', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S6', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S6', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S3', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S1', 'model':'^(PTX1|QFX1)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2-S1', 'model':'^(PTX1|QFX1)', 'fixed_display':'22.1R2-S1, 22.1R3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R1-S2', 'model':'^(PTX1|QFX1)', 'fixed_display':'22.2R1-S2, 22.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
