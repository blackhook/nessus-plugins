##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163629);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-22205");
  script_xref(name:"JSA", value:"JSA69709");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos OS DOS (JSA69709)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A Missing Release of Memory after Effective Lifetime vulnerability in the Application Quality of Experience (appqoe)
subsystem of the PFE of Juniper Networks Junos OS on SRX Series allows an unauthenticated network based attacker to
cause a Denial of Service (DoS). Upon receiving specific traffic a memory leak will occur. Sustained processing of
such specific traffic will eventually lead to an out of memory condition that prevents all services from continuing
to function, and requires a manual restart to recover.
 
A device is only vulnerable when advance(d) policy based routing (APBR) is configured and AppQoE (sla rule) is not
configured for these APBR rules.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69709");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69709");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

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

var model = get_kb_item_or_exit('Host/Juniper/model');

check_model(
  model:model,
  flags:SRX_SERIES,
  exit_on_fail:TRUE
);

# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'20.3R1', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S2'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S1', 'fixed_display':'21.2R2-S1, 21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S2', 'fixed_display':'21.3R1-S2, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
