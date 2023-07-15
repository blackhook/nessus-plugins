#TRUSTED 4b668dc7d374cf678b4d14add498d9e8fb37299750e7cc20decc33a7e348d850032ee93dbb3a901ee845b1df2305c40396b89f5a74de076e6fa74ea1cea5ac1d723ce1e4945ad594b09c3248f166309cfe55b1f8dd95b203255be301b1298adeccea8be928b624c28babe6136be0814a8cdddbdc00bca4a0a5ecbd07113a7a7b2037045d9bac3b9b2bda31d54c7904a010128a0848d5d55b8382ca87f4d674c894598ec1bfae7d81bc502a123eaf0b1dcc972a716cab3c274fb68e5480a4907363da6068e0cf6dbfadd87a1f5dc586bf607f679148ab8a8cece7088a094c07ced56f7906ef4a70696906d2015bc3c25d3966a71be0b15016cdeb9f9ecdb7e56963c7e8184f9358097cbd2b7b4746fdf1707ea0feff64a8bc68f36b751cf204319903928a1b80dff8e7f42a364f247e9335e431143497017c73eaacd19e7d55ad995f4ee890db01bc780ec186ef38c4713af826b2ede665a9b3df7d1e668197c85997c7031621581fc1582f3e3d1df250952f2ed0677949861f3f2703ab41b956adfa3c2b3acc0f0bb096cc321058fa46d6f191a7ae1e04c47fd571a3106ba2e39ba9fe7cb8b95657c91eb75a5ca61787e348b25465311d6ac05c80090ed64381c679acd53401e6accf8b408a2f7de88954d53695893ce5e0a81fd7fd11f4aba2b05e0915c95ab60a3752e8d540af4d0a2236bfaa3140cd9edcf7222bc51f8a33
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133863);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-1602", "CVE-2020-1605", "CVE-2020-1609");
  script_xref(name:"JSA", value:"JSA10981");

  script_name(english:"Junos OS Multiple vulnerabilities (JSA10981)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by 
multiple vulnerabilities:
    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv4 packets who may remotely take over the code execution of
      the JDHDCP process. (CVE-2020-1602)

    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv4 packets who may then arbitrarily execute commands as root
      on the target device. This issue affects IPv4 JDHCPD services. (CVE-2020-1605)

    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv6 packets who may then arbitrarily execute commands as root
      on the target device. This issue affects IPv6 JDHCPD services. (CVE-2020-1609)

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10981");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10981.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('misc_func.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['15.1R'] = '15.1R7-S6';
fixes['15.1X49'] = '15.1X49-D200';
fixes['15.1X53'] = '15.1X53-D592';
fixes['16.1'] = '16.1R7-S6';
fixes['16.2'] = '16.2R2-S11';
fixes['17.1'] = '17.1R2-S11';
fixes['17.2'] = '17.2R2-S8';
fixes['17.3'] = '17.3R3-S6';
fixes['17.4'] = '17.4R2-S7';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3-S2';
fixes['18.2X75'] = '18.2X75-D60';
fixes['18.3'] = '18.3R1-S6';
fixes['18.4'] = '18.4R1-S5';
fixes['19.1'] = '19.1R1-S3';
fixes['19.2'] = '19.2R1-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


# If forwarding-options dhcp-relay, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set forwarding-options dhcp-relay";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);