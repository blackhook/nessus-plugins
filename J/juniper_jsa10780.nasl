#TRUSTED 8c7ddaa3be2d286174fd7faa4326b3460c53b9df104b381870f3fce67adf78f4268139c870437005ddbb2cf348ca502830dd7148b8eceb182b4f219a2cbed6381a56ee18f2c7532004d2817cf969b72902b832b944930df6e603e8830337206e58702f46c37c4656ae7a72aab5f70ebc0baea138c7ca30739a91e6cbfb38a57bc76e7fb413f5b114017c58b94aea460d07866af703592d37f845d5367992cecd464ed49ac4734d11a371d47be0bf5f89c249b0c460737cba5d8af40025a963e3c258f1bebcd37176fde4e8308462216fafaba96420a1993e534ae40a6d3188131ee1b8b4a8f047772041994d699e897afb7e19c90b094dca324782762cb11725cc1c1c5b05ef93a01104b389632cf8ecb6921b1aedec44a54c10d723ab27a8d33f7d949eee513f6904e436a2dc8da922cbbb1d89d6e69b60a77c8ee22fac187959e687c345d06adcaac82cccf7e8a2ff6cdefe0749b01fd454e3232c5d5d34ea86808b8ca2ea19a5b8b45b43e22c656958b5228278c955f75980fc1c0478f95c1eb7bb9ce1a926dcba60111200221270f8695f0e8ad54aa21d9b85b9a359a83373af73b7956a2f13c0527da88a0cbb8e1c5990b61907db3bc3f4f4e12e377a43cebf26ed9a6927caf39dc60d8152e0730471d01862a26c0b03b3f3af758acc267fc42878f3f7ee86afb5fa827c867f41c1ff8e9be19d7aecbe0e2bca150773fd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101266);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-10142");
  script_bugtraq_id(95797);
  script_xref(name:"JSA", value:"JSA10780");

  script_name(english:"Juniper Junos ICMPv6 PTB Atomic Fragment DoS (JSA10780)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability in the
ICMP Packet Too Big (PTB) message functionality that occurs when
handling IPv6 atomic fragments that trigger fragmentation in traffic.
An unauthenticated, remote attacker can exploit this issue, via a
specially crafted series of packets, to cause the device to stop
responding, the exhaustion of resources, or other impact that results
in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10780");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10780.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

fixes['12.3X48'] = '12.3X48-D50';
fixes['14.1R8'] = '14.1R8-S3';
fixes['14.1X53'] = '14.1X53-D43';
fixes['14.1'   ] = '14.1R9'; 
fixes['14.2R7'] = '14.2R7-S6';
fixes['14.2'] = '14.2R8';
fixes['15.1F2'   ] = '15.1F2-S16';
fixes['15.1F5'] = '15.1F5-S7';
fixes['15.1F6'   ] = '15.1F6-S5';
fixes['15.1F7'   ] = '15.1F7-S1';
fixes['15.1R4'] = '15.1R4-S7';
fixes['15.1R5'] = '15.1R5-S2';
fixes['15.1X49'   ] = '15.1X49-D80';
fixes['15.1X53'  ] = '15.1X53-D231'; 
fixes['15.1'] = '15.1R6';
fixes['16.1R3'] = '16.1R3-S3';
fixes['16.1R4'] = '16.1R4-S1';
fixes['16.1'  ] = '16.1R5';
fixes['16.2R1'] = '16.2R1-S3';
fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R1'; # or 17.1R2

override = TRUE;
# Check if IPv6 is enabled
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces .* family inet6 ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  override = FALSE;
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "17.1R1")
  fix += " or 17.1R2";

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
