##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163331);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-22216");
  script_xref(name:"JSA", value:"JSA69720");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos Information Exposure (JSA69720)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An Exposure of Sensitive Information to an Unauthorized Actor vulnerability in the PFE of Juniper Networks Junos OS 
on PTX Series and QFX10k Series allows an adjacent unauthenticated attacker to gain access to sensitive information. 
PTX1000 and PTX10000 Series, and QFX10000 Series and PTX5000 Series devices sometimes do not reliably pad Ethernet 
packets, and thus some packets can contain fragments of system memory or data from previous packets. This issue is 
also known as 'Etherleak' and often detected as CVE-2003-0001.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA69720");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69720");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
var vuln_ranges;
if (model !~ '^PTX1(0{4}|0{3})$|^PTX50{3}$|QFX10{4}$')
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

if (model =~ "^PTX1(0{4}|0{3})")
{
  vuln_ranges = [
    {'min_ver':'0.0', 'fixed_ver':'18.4R3-S11', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.2R3', 'fixed_ver':'19.2R3-S4', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.4', 'fixed_ver':'19.4R2-S5', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S6', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2', 'model':"^PTX1(0{4}|0{3})"}, 
    {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4', 'model':"^PTX1(0{4}|0{3})"},
    {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'model':"^PTX1(0{4}|0{3})", 'fixed_display':'21.1R2-S1, 21.1R3'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1', 'model':"^PTX1(0{4}|0{3})", 'fixed_display':'21.2R1-S1, 21.2R2'}
  ];
} 
else if (model =~ "^QFX10{4}$|^PTX50{3}")
{
 vuln_ranges = [
    {'min_ver':'0.0', 'fixed_ver':'18.3R3-S6', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'18.4', 'fixed_ver':'18.4R2-S9', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S10', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.2R3', 'fixed_ver':'19.2R3-S4', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S6', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3', 'model':"^QFX10{4}$|^PTX50{3}"}, 
    {'min_ver':'20.3', 'fixed_ver':'20.3R3-S1', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1', 'model':"^QFX10{4}$|^PTX50{3}"},
    {'min_ver':'21.1', 'fixed_ver':'21.1R2-S1', 'model':"^QFX10{4}$|^PTX50{3}", 'fixed_display':'21.1R2-S1, 21.1R3'},
    {'min_ver':'21.2', 'fixed_ver':'21.2R2', 'model':"^QFX10{4}$|^PTX50{3}"}
  ]; 
}  

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
}
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);