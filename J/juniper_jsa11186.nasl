#TRUSTED 0c1cf68db8d807b973e21dda90f0f818b8a0b6ae647a4194bc7e91e8595f92ad05739cf703271fff933bc9d9b57b120283e1b0674ec6f3b3bcced6a110c238d4872af56cbe94b520bcb831cc8ee5db122273bce98d1433fb0cf72e8f9c97ae3a14867732c521b698d31d2c15d38bca1f32caf5e4ee8fabd691c7fa391e28846ebc820c2dda1b5fd8209dad6c26799d471b4e636841e6746e12230a302ad19fb26aee4ef39ee64433a2d351d5a9c399a87a005aa2f9e2a817ad118986103efcca3bc0f3ab91f4de3d65324a3807bfa9e321a8d7ab8457b3fe7b059178a140f352c81758edc5721e52db3343dbca3c89f5a4249554f867a4c2dc9bf7e5f259d9a05363f854025aecebc91942be9d668ee0da2895115982e10e93054595369298ec1f15077eb43eeda75b6147670a8cd3724bf404ebb3dafe7c3abab140c4072d9e22cecf1cf66fce20d8d0b03771a4023cbee97b0975e8ff0dc5f9d85187ffed136a36bc1dd664f473f909b7c16be619a544ea2d973225b7821fb0e78306c6910bedbfc1d9033d01e2165fbbeb69f11126e4bcd3d96540c02804ad258b1dfdeaeff180cffd73da9c30a5ef0efd84e95c16108e6d2a8272a52628ecccb5dd2634b9ee89d9fa8c6bfb6442a761038dbce1714e8325a7aa6dbed4def3d38cc8a372d55e07f42492caace883016ea2cd62424a4fe1d61ae095cd6f46d46106c4c41c25
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153256);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-0282");
  script_xref(name:"JSA", value:"JSA11186");
  script_xref(name:"IAVA", value:"2021-A-0324-S");

  script_name(english:"Juniper Junos OS DoS (JSA11186)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as
referenced in the JSA11186 advisory.

  - On Juniper Networks Junos OS devices with Multipath or add-path feature enabled, processing a specific BGP
    UPDATE can lead to a routing process daemon (RPD) crash and restart, causing a Denial of Service (DoS).
    Continued receipt and processing of this UPDATE message will create a sustained Denial of Service (DoS)
    condition. (CVE-2021-0282)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11186");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11186");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'12.3', 'fixed_ver':'12.3R12-S18'},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S9'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S11'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S13'},
  {'min_ver':'17.4R3', 'fixed_ver':'17.4R3-S4'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S12'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S7'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S6'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S3'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set protocols bgp.*multipath", multiline:TRUE) && 
      !preg(string:buf, pattern:"^set protocols bgp group.+family.+add-path", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
