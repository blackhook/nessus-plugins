#TRUSTED ac9c13f1f10431a7f17e7f9ba29e7b874c273f6dbd38798be8bc9f232108b20c92e7f51ee99cd8b7d4dd00ac7f4e6c2ab5a96bcf5d71e694f9aaccbd32984f94363ccabc5b939e958b23bf85108a023d4e06f181c768945fd07db2a9de0075b55d5ae4350cd6d25893852a046709dd155a824bb1ae50d896be9dfc923f2db41dc0f907ce2ab47cffa70332de8b6ce5f1c3ccc782f25f2b7b34db79b0050c87af70adcba12911ecc979a2ee1be38ff9efd002b30244284919961729aff33fa048ec2ad4c3fd15892c266c24aed5950707c9e3c612a7ef466176c994e7dbd4ee3430d1012fa23880d5b23e098576129bf00ddc132e945527049c1431544570130b955ab46934f23169e18336d869ff6862d0ea797ed96c9eb0b8aefe3d854ffe1e4ada7e0fbd5037386614f2b4c3373b0b92f346a94703fded6b1b0438713ae28faa30fa4dc2468d3dc8b135c7e4857bbd8a3c05d9124da4e44f58fdb6f90391ec250c1890418405d2c0ebd3ebcc5d2ff7171b2c7d1a6b04da6702542971518beb703ff4e8da9a0734abff5fcd875e289dcb929b2446b07cfb89e42e4e858690e2a1f6faad081b13ebe225a63d8d27128d776f02459e840c0bf176d46c3b80f986595fc51e75ecc3bf3cf29220de21c8d26129dea0b3c586e1be9fc095ab484f9f30d4633564e6111008d838cb5eb33409c6ba662a7e105cb7b6961c41e17976a6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161264);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2021-0299");
  script_xref(name:"JSA", value:"JSA11213");
  script_xref(name:"IAVA", value:"2021-A-0478-S");

  script_name(english:"Juniper Junos OS Kernel Crash DoS (JSA11213)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11213
advisory. An Improper Handling of Exceptional Conditions vulnerability in the processing of a transit or directly
received malformed IPv6 packet in Juniper Networks Junos OS results in a kernel crash, causing the device to restart, 
leading to a Denial of Service (DoS). Continued receipt and processing of this packet will create a sustained Denial 
of Service (DoS) condition. This issue only affects systems with IPv6 configured. Devices with only IPv4 configured 
are not vulnerable to this issue. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11213");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11213");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.4', 'fixed_ver':'19.4R3'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S1', 'fixed_display':'20.2R1-S1, 20.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
#command found at: https://www.juniper.net/documentation/en_US/junos/topics/topic-map/ipv6-interfaces-neighbor-discovery.html
var buf = junos_command_kb_item(cmd:'show interfaces terse');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"inet6"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
