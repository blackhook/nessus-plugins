#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160200);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-0298");
  script_xref(name:"IAVA", value:"2021-A-0478-S");
  script_xref(name:"JSA", value:"JSA11212");

  script_name(english:"Juniper Junos OS DoS (JSA11212)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11212
advisory.

  - A Race Condition in the 'show chassis pic' command in Juniper Networks Junos OS Evolved may allow an attacker to 
    crash the port interface concentrator daemon (picd) process on the FPC, if the command is executed coincident with 
    other system events outside the attacker's control, leading to a Denial of Service (DoS) condition. Continued 
    execution of the CLI command, under precise conditions, could create a sustained Denial of Service (DoS) condition. 
    This issue affects all Juniper Networks Junos OS Evolved versions prior to 20.1R2-EVO on PTX10003 and PTX10008 
    platforms. Junos OS is not affected by this vulnerability. (CVE-2021-0298)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11212");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11212");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
var model = get_kb_item_or_exit('Host/Juniper/model');

if (model != 'PTX10003' && model != 'PTX10008')
  audit(AUDIT_HOST_NOT, "an affected model");

var vuln_ranges = [{'min_ver':'0.0', 'fixed_ver':'20.1R2-EVO'}];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);

if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var report = get_report(ver:ver, fix:fix);

security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);