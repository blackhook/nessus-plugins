#TRUSTED 97f0d45898a12069cd255e8415a7174f7491c12c7e644418d3dcf6214118dde5e92cd32a9d2079b615f4cf99e366561321b2f4b29a1978ba28da0aaf5a03b5b8bddd9e3ac3427b5a95c1aeca06986f5e79645fa51832acdaa7817710fccf26a1fd1ffb3d3efdf679194e3b8410a51ddad35b5a80ef0e0e6743e6d922906a9f40490d79f53cd50a33e9a45513b859db4bf492a32d5299e865aa84fbb4efb33eafd047210d1d158e8a2761fbd928bfb75b908e79e930c08ce007b93f54f480eaeae60c006284392f9bcd2eaf2c1fdfa5f25f26e4bdb146f92a838fe91e7808e42c57b5142f85fa96a16b3c233da7812507a6c05fad5b2472d65cdb269bbc20a4a725c0b715fc5920fb8fb0a93edd2983f1cc369c03828a084ab7988a18a0b7354fbbb3172dd5cebf4fa6807064ad24a1d8662e4d7d5775ee4965fbdc448c4011d151988d5037698ee68676ad7119308312dd3c35c7371bb4e1091922bbcdb4f09c43330679d7281c0cba36f135f857abece6cae6161348dcaa0d54abdef517048ee0eac6db8e012f62ab51c1c8bbeb5eaf0603d0504bff42a40a2b98318b7f15d3d03705e5bd9b1564dfd528004a7b7a82abd0c18818c73280f50a4c5ff7074d0355e268622df9120e01a5154a1b57da4558d472f202ca5fe57b9206b60d29102ef9fa75232acb71b883cb0ecc5d47a40abebeb05ff1e17613e28add9d7dc62f0a
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161261);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2021-31367");
  script_xref(name:"JSA", value:"JSA11229");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS FPC Crash (JSA11229)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11229
advisory.

A Missing Release of Memory after Effective Lifetime vulnerability in the Packet Forwarding Engine (PFE)
of Juniper Networks Junos OS on PTX Series allows an adjacent attacker to cause a Denial of Service (DoS)
by sending genuine BGP flowspec packets which cause an FPC heap memory leak. Once having run out of memory
the FPC will crash and restart along with a core dump. Continued receipted of these packets will create a
sustained Denial of Service (DoS) condition. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11229");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

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
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^PTX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'18.4R3-S9', 'model':'^PTX'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7', 'model':'^PTX'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7', 'model':'^PTX'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3', 'model':'^PTX'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R2-S6', 'model':'^PTX'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S3', 'model':'^PTX'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R1-S4', 'model':'^PTX'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R3-S6', 'model':'^PTX'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'model':'^PTX', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S1', 'model':'^PTX'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3', 'model':'^PTX'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3', 'model':'^PTX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2', 'model':'^PTX'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show protocols');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:".*protocol bgp.*family inet flow", multiline:TRUE))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
