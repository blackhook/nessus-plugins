##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-22188");
  script_xref(name:"JSA", value:"JSA69497");
  script_xref(name:"IAVA", value:"2022-A-0162");

  script_name(english:"Juniper Junos OS Heap-based Buffer Overflow (JSA69497)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An uncontrolled memory allocation vulnerability leading to a heap-based buffer overflow in the packet forwarding 
engine (PFE) of Juniper Networks Junos OS allows a network-based unauthenticated attacker to flood the device with 
traffic leading to a Denial of Service (DoS). The device must be configured with storm control profiling limiting the 
number of unknown broadcast, multicast, or unicast traffic to be vulnerable to this issue.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69497");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69497");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

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
include('junos_kb_cmd_func.inc');

# Added paranoid cehck, cant verify the config check mentioned on the advisory
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "(^QFX5(1(0|1|2)|2(0|1))\d|^EX46(0|5)\d)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var vuln_ranges = [ 
  {'min_ver':'20.2R1', 'fixed_ver':'20.2R2', 'model':'(^QFX5(1(0|1|2)|2(0|1))|^EX46(0|5))'} 
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
