##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148679);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/05");

  script_cve_id("CVE-2021-0263");
  script_xref(name:"JSA", value:"JSA11154");

  script_name(english:"Juniper Junos OS Vulnerability (JSA11154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11154
advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11154");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11154");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0263");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^PTX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S7'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S8'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S4'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S1'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S2'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
