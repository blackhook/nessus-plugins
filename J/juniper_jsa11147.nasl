#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149453);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-0254");
  script_xref(name:"IAVA", value:"2021-A-0180-S");
  script_xref(name:"JSA", value:"JSA11147");

  script_name(english:"Juniper JSA11147");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11147
advisory. A buffer size validation vulnerability in the overlayd service of Juniper Networks Junos OS may allow an
unauthenticated remote attacker to send specially crafted packets to the device, triggering a partial Denial of Service
(DoS) condition, or leading to remote code execution (RCE). Continued receipt and processing of these packets will
sustain the partial DoS. The overlayd daemon handles Overlay OAM packets, such as ping and traceroute, sent to the
overlay. The service runs as root by default and listens for UDP connections on port 4789. This issue results from
improper buffer size validation, which can lead to a buffer overflow. Unauthenticated attackers can send specially
crafted packets to trigger this vulnerability, resulting in possible remote code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11147");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11147");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

if (model =~ "^SRX")
  audit(AUDIT_DEVICE_NOT_VULN, model);

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'JUNOS', ver);

var vuln_ranges = [
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S6'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);