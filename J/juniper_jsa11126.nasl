#TRUSTED a9d3c838ed7919c8e673fe75fee3eefd0945d0a5bb4f440248421e25168c51c2a3514f4476d684ca44bdf82bb78b6512c5955c4e712666248c2cecd7e06617a56943a16cc05659787ecd8967aa1615cc456d00595afeaddb90a3129495efbb95742f12345b926362392d2dda27de0cacde477739c7c1bc97db45ee2d778bdfd41e88bc4052db0969ca32b32c4979fbcf39cd4bfe208da4b09c5d3b5b3890d0a66a7ab648243e6c30a94c841f00a4b5e3e4bb4508c22bd6ff4d1fb15490c0943d8168ee548b9b1cf0a16c9617a01e510a695e61486f594e197aefcc2bbbe3f1fd4741ec725fe36d2e723d9bf28e293d04ef379fe96e29e29dc8d3bcf2f7502392e43abf4d69f0aa6e5dbe336577d48438854beb0454816fd2eb5ecb09b6920caf9fb7da3d9541254a0256bb92fac87f508c68e463595b3f49fedd7bb472458014d38b85941083598964a829e531a4b457180e4b0998bddf0903904aabbbbaaec8fa46b7bfb6bb4c489c5a76e865f59fe6a4abcae9a46f656dfa587ff4ca9c8b51ce62fe1616d7c1c6237326ad2592e0f0eaad3f9c37394c7ed83fb81072ed94fb37b1b0c3ab7ef35c5f65b148e03050f0a8e9679bfc14bdb49e4e2e0b4dea3aa599d61f3fd58c1384888cbb8a3e5f6985f603c4b6bb52e240659bc24d261ef0e7773736c8a99d04bda8104ddc85c4236fb1d6abbc23e262fc9061d983b84fa96d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149473);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/13");

  script_cve_id("CVE-2021-0231");
  script_xref(name:"JSA", value:"JSA11126");

  script_name(english:"Juniper Junos OS Information Disclosure (JSA11126)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by an information disclosure vulnerability. A path
traversal vulnerability in the Juniper Networks SRX and vSRX Series may allow an authenticated J-web user to read
sensitive system files as referenced in the JSA11126 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11126");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11126");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0231");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

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
if (model !~ "^(vSRX|SRX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S4', 'fixed_display':'19.4R2-S4, 19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1-S4', 'fixed_display':'20.1R1-S4, 20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S3', 'fixed_display':'20.2R1-S3, 20.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

#set system services web-management https interface vlan.0
var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set system services web-management", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
