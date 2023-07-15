#TRUSTED 245d080133e7c7f31aef3570b3f58a4fb381d46795b7ce7d0711e0dc41e3a33356fab727ad87f0763b814f9e5804a5e09bd01da2c2a9b0f90a84c56f1445fe96825c72dc12d20500fedefdde4991c04100a847367ddeac581b7cfefc4920cbbbaf7032e371d46596d43e4a308c19b4f352478dc194e8089ea2fecf0ba8cbf17502ebf87b9c6b5674f27b67c1601e7407bc54eaf7014b2489a41cebf51b1301fad0dd90091b8d756c50b90f9d2efa3dbcd7a004237ba07a8ee6ab6989b8cc6187d82391494ad7253b00519f282293c70f90b5c4171873ef4182a308b55b8635e6a11277dcf74bc5598761933e13e2369156db56ac72591e958c35ae80626f2563812a3a35585b5382dc9cd1e5e5371826b33851d72340bff29c51628a28c5619501181cecd1b77c3216a137144b6ddfae815a26a7e66cd089b1d75a7f0eb8a6a860c8a42bb24addf4ed752b436406940a4fe987319c0c96375cc0d5a1b1e582dec9e69c71c4511a9b0543cbfd939b5246b0c46c097f9f7a336042513bebac9255c6437217911247bd663aaa0bd8e52f4f482e91df220992a2d724119c0b92cb377f9749c80f4542a4b42e91041bb74d7e2ee1cb2a7619a3a10e9e75d6e388f0d725b960d09cbca1ca36a2aa6c4cb5a2f876dbe7e362fd179dbabe218dd66073ca7acd74cd51da70a2b3d61f7f7ecc67228bd3d444097b17b4e2e0b5fcc593f9c7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130468);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0059");
  script_xref(name:"JSA", value:"JSA10957");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: rdp Memory Leak DoS (JSA10957)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a memory leak
vulnerability in the routing protocol process (rdp) which can result in a denial of service (DoS) condition. An
unauthenticated, remote attacker can exploit this issue, by sending specific commands from a peered BGP host and having
those BGP states delivered to the vulnerable device, to cause the system to stop responding. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10957");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10957.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0059");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
# Note that the advisory has contradictory information in the problem and solution sections. 
# This plugin follows the solution section.
fixes['18.1'] = '18.1R2-S4';
fixes['18.2'] = '18.2R1';
fixes['18.2X75'] = '18.2X75-D5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If BGP is not enabled, audit out.
# Same as juniper_jsa10799.nasl
override = TRUE;
buf = junos_command_kb_item(cmd:'show bgp neighbor');
if (buf)
{
  override = FALSE;
  if (preg(string:buf, pattern:"BGP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
