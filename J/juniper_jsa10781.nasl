#TRUSTED 4dcdfaccb53c4190d29d4ee2de7eb676fc5a6f4f89468ba301ec49c56a4b188ebfccfb14ddcd1e4cdc9bd16053fa64ea4b5422c31f75306248987aa3315712f308457ef4168b7023e19095317cab30aeed12f50e760338d6e597a08d528dee69a95b9eff9ba44897d4262d20f1b5f5f176f08b89c2fb30031dee612c107961c102eac70f9bd9c9fbf336c4f975cadb181c84a2ffa075db545b830a66be79f5f3a3385239b5ed04e080d9d782166aa920b4f06ffdcf6254c0361883dd9d52d83fabcd182ffd4466e678a928a094e676ca99e536f6105d1091a5cfb84a4db4ee5e4296fdbe95d6e7d759609118400e7134ed3dcf45a99f0fe70161b9e2b0da7f6f0cdb653ad417725f888100702e94ff2f3e1944b7a24818e962d0780a09ea66769b12d35ebe21f0a4dd872346eac804fc8b20190dc2d388d81cd6b71bd59be61a598740eab26d8b59c3dd5e9364936d33a215c0ca3b1089713da75a54b3ef3ba8d182378db0e2c14f34d7d81c636ce2e2a027404b65f86b504d97faae291d566acec064b7b98799873bc92995ddc1d9acd680ccc669e1b3d4778fe300bbc9dee7fd0eff6df100746568f6428353e2ec419778a30b9283897a01dc928da53e4f45accc34801e75af076ad3bf798c3358f1d8b1fb66ae7018119540eef6dcdbcab1436bb86bd5b4385ce335404d55d1411b97ac6b11c25e58aafbe407c7386ca0e1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99526);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2315");
  script_bugtraq_id(97615);
  script_xref(name:"JSA", value:"JSA10781");

  script_name(english:"Juniper Junos for EX Series Switches IPv6 Neighbor Discovery DoS (JSA10781)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Juniper Junos EX
Series device is affected by a memory leak issue in IPv6 processing
when handling a specially crafted IPv6 Neighbor Discovery (ND) packet.
An unauthenticated, remote attacker can exploit this, via a malicious
network-based flood of these crafted IPv6 NDP packets, to cause
resource exhaustion, resulting in a denial of service condition. Note
that this issue only affects EX Series Ethernet Switches with IPv6
enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and model.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10781&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae19d456");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10781.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^EX")
  audit(AUDIT_HOST_NOT, 'an EX device');

# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['12.3R12'] = '12.3R12-S4';
fixes['12.3'] = '12.3R13';
fixes['13.3'] = '13.3R10';
fixes['14.1R8'] = '14.1R8-S3';
fixes['14.1'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D12'; # or 14.1X53-D40
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2R6'] = '14.2R6-S4';
fixes['14.2R7'] = '14.2R7-S6';
fixes['14.2'] = '14.2R8';
fixes['15.1'] = '15.1R5';
fixes['16.1'] = '16.1R3';
fixes['16.2R1'] = '16.2R1-S3';
fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
