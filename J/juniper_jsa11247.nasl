##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161525);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/27");

  script_cve_id("CVE-2021-31379");
  script_xref(name:"JSA", value:"JSA11247");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS DoS (JSA11247)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11247
advisory. An Incorrect Behavior Order vulnerability in the MAP-E automatic tunneling mechanism of Juniper Networks
Junos OS allows an attacker to send certain malformed IPv4 or IPv6 packets to cause a Denial of Service (DoS) to the 
PFE on the device which is disabled as a result of the processing of these packets. Continued receipt and processing 
of these malformed IPv4 or IPv6 packets will create a sustained Denial of Service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11247");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11247");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include('junos.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');
check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'17.2R1', 'fixed_ver':'17.3R3-S9'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S12'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S11'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S6'},
  {'min_ver':'18.2R3', 'fixed_ver':'18.2R3-S3'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3', 'fixed_ver':'18.3R3-S1'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R2-S5', 'fixed_display':'18.4R2-S5, 18.4R3'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S6'},
  {'min_ver':'19.1R2', 'fixed_ver':'19.1R2-S2', 'fixed_display':'19.1R2-S2, 19.1R3'}, 
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S5', 'fixed_display':'19.2R1-S5, 19.2R2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S5', 'fixed_display':'19.3R2-S5, 19.3R3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
