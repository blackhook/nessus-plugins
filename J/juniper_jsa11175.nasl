##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148649);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-0255", "CVE-2021-0256");
  script_xref(name:"JSA", value:"JSA11175");
  script_xref(name:"IAVA", value:"2021-A-0180-S");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11175)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11175 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-
reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11175");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11175");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S7'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S1'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
