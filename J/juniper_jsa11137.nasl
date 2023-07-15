#TRUSTED 91e1e4950aa5fbc7056e038786dbffd258a25edd21f57cb8240b5db4062beab7b1a3d0174a2c7417d311538e728ece5b8ffc0d877d144086761d2ae808ceef569230e2a7b8a559c9f399e393f2b72677b286fee4097d2d5e89380a62f6665888ad438220a244e2cf1c73697f29206e8f86a9e31f975544e704a3ab87e5e904b877adabb107f17ef7d5646fa60a6b2db5d5a80aba39aa9b5945fc9245fb59f0a00fdbd9cbcaa9864375e0f6448e5a48160870a163071e5303814b90b0f5e951f15770000e6264d6bdf9fd222d6006de5bff51b31c0be314ab19d9fa1daf3fe2eb55f9039b7211e6172da02aebe8bc2dc410519d008745cb6ab088e6a3ba62f0a39f5b719b3fd6d518f0eb6d70319e173f2fc7ce0eaf4fe55d9e82e2bff4a01c913d7dbcf89c1d0421e29953abcd801a178abed764ab107dad67505aee94fd7c07056e8de82174cdd4908360ad4e394fff4f7ec23b4f16cf1931833bc9c61f135cd4619be46c4b37f445f8ec6c002894e842408488599ea57139e3d73c32ef7e44d2a8ec3eb679fe1c51e615b0d61884f4c8287e99e9a692f1e50c4132a81174d95160d2ace8d1cc7dd70eee572cd62acaf78a9111e8468a192d22ceec86767c5c4464c97c254f5bf9698ef3286a51ca5e1ab135f5f3e880aaaf5e06a5c779bd7ab8fc9a0c8be3f0d1058478d690526242d11e7adf1aa1546ea8d84082052111f0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149369);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/12");

  script_cve_id("CVE-2021-0244");
  script_xref(name:"JSA", value:"JSA11137");

  script_name(english:"Juniper Junos OS DoS (JSA11137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in
the JSA11137 advisory. An unauthenicated remote attacker can bypass the storm-control feature on devices due to a rare race
condition exists in the Layer 2 Address Learning Daemon (L2ALD) of Juniper Networks to cause denial of service (DoS).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11137");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11137");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

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
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'14.1X53', 'fixed_ver':'14.1X53-D49', 'model':"^EX.*"},
  {'min_ver':'15.1', 'fixed_ver':'15.1R7-S6'},
  {'min_ver':'15.1X49', 'fixed_ver':'15.1X49-D191', 'model':"^SRX.*", 'fixed_display': '15.1X49-D191, 15.1X49-D200'},
  {'min_ver':'16.1', 'fixed_ver':'16.1R7-S7'},
  {'min_ver':'16.2', 'fixed_ver':'16.2R2-S11', 'fixed_display': '16.2R2-S11, 16.2R3'},
  {'min_ver':'17.1', 'fixed_ver':'17.1R2-S11', 'fixed_display': '17.1R2-S11, 17.1R3'},
  {'min_ver':'17.2', 'fixed_ver':'17.2R2-S8'},
  {'min_ver':'17.2R3', 'fixed_ver':'17.2R3-S3'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R2-S5'},
  {'min_ver':'17.3R3', 'fixed_ver':'17.3R3-S7'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9', 'fixed_display': '17.4R2-S9, 17.4R3'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S5'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S6', 'fixed_display': '18.2R2-S6, 18.2R3'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7'},
  {'min_ver':'18.3R2', 'fixed_ver':'18.3R2-S3', 'fixed_display': '18.3R2-S3, 18.3R3'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S5', 'fixed_display': '18.4R1-S5, 18.4R2'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S4', 'fixed_display': '19.1R1-S4, 19.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
#set storm-control-profiles profile-name all bandwidth-level kbps 
var override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set storm-control-profiles.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
