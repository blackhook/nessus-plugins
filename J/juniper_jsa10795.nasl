#TRUSTED 6718e1677989244d6ec2119eef00d2fb522eb91d11eda65cdce39477902b1432cb0c41e0d70662a1232fec5f8b8dcba57b95fe8e04f9cbaea1154fddd333e3a8871c6ef277d76d2dcb8db9299ac84b3a2947841999cfd169157d67388bb3a4d7c605ad277192df3a9e4e0ee9319c733e6398c702579bced2a6952ca96a3a132392fa2c7a12627b135a8720d20811ff4ec25b80a6b9b1a14f34dba37c7a435b208a91716081ca23718095d7fe7346ab263295936b5b0325e76b2a7a945af343930d1ed41549b761c1c293b34402e93f5d250f62ee6ff8773bfc344c179d6665171a75b961d76f73122d3e99a065a9d0d7e8a437bbf6dd9e8a377ad557e89175e569ebb9519d7244aee5b271913db897b950004d15a67e80180b4ec650ef94bbbf0347402abefe4ff9b8136bb536e32459dd81ddd727b2e00a5bf181ab33198d7a60366d422e37726f53f09cda1bbdb121840a7cd731c313e661b366eb22a6f2552db0aca33098a599529c6e9cbacc7c310e86634948c0ea1dcdab12e631a50f4d1b07bc456721a41cb27749bc14460a1ec21784a0e5983401386fff994621ab77d827618d0bdce647a5c9f4853444ee2fd6ff327b58b2bdd8d39bf18fb70d7a1b357765d380b7a3777c2e0aae6b4fdd9d41114f12d958372b26962616a5507129f6de0c2e0de08a7f2676479812a56a6248df4286078bc9ef1b480399db151610
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102708);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2347");
  script_xref(name:"JSA", value:"JSA10795");

  script_name(english:"Juniper Junos rpd MPLS Ping Packet Handling DoS (JSA10795)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the rpd daemon due to improper handling of MPLS ping
packets. An unauthenticated, remote attacker can exploit this, via a
specially crafted MPLS ping packet, to crash the rpd daemon.

Note that the device is only vulnerable if MPLS OAM is configured.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10795");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10795.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.3X48'] = '12.3X48-D50'; # or D55
fixes['13.3'] = '13.3R10';
if (ver =~ "^14\.1R4")        fixes['14.1R'] = '14.1R4-S13';
else if (ver =~ "^14\.1R8")   fixes['14.1R'] = '14.1R8-S3';  
else                          fixes['14.1R'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D42'; # or D50
if (ver =~ "^14\.2R4")        fixes['14.2R'] = '14.2R4-S8';
else if (ver =~ "^14\.2R7")   fixes['14.2R'] = '14.2R7-S6';
else                          fixes['14.2R'] = '14.2R8';
if (ver =~ "^15\.1F2")        fixes['15.1F'] = '15.1F2-S14';
else if (ver =~ "^15\.1F5")   fixes['15.1F'] = '15.1F5-S7';
else if (ver =~ "^15\.1F6")   fixes['15.1F'] = '15.1F6-S4';
else                          fixes['15.1F'] = '15.1F7';
if (ver =~ "^15\.1R4")        fixes['15.1R'] = '15.1R4-S7';
else if (ver =~ "^15\.1R5")   fixes['15.1R'] = '15.1R5-S1';
else fixes['15.1R'] = '15.1R6';
fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D47'; # or D62, D70, D105
if (ver =~ "^16\.1R3")        fixes['16.1R'] = '16.1R3-S3';
else                          fixes['16.1R'] = '16.1R4';
fixes['16.2'] = '16.2R1';
fixes['17.1'] = '17.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

#If MPLS isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set protocols mpls";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have MPLS enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
