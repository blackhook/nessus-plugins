#TRUSTED 0d43943ffd5ff1b0c34511c0a603ebae19ca67481bff4f578779523291ed76196abd6e0f55d153ad9ee628e3cdf68854d9ed7dbbec969622b53589ec0657010268f28a69738d1bc8ad261a036f99abc12bd510e17da16873aecd849f7357fda19caf936de8a7cdd9ec9786c95fed6491f3c12cb273e2f7e71a861f3f5ace901c493d757a04bc393798e1310b5cce28258a6deb0bca33882b18418cae93f3106464969e43880304e2dc8f4d6d5d416ed0c9e84675a09cd70bca603cf5095adafeea2fd17f689665e54daa85cfcbd0cd3e724c203c8d300bb276b52ef61d439b3634744b4a9321ab5c166c78fea7823449c91a52ad6597a01a6a944a78c38a4e20db677ad815985b40ccf6dc1d80b34c8c06aacc6371735c5328f466943f140e27c8ba7ab659ea24a764d0bdb5413bdc8322d93f960bcedcd6bea87f50d549d225aedbbddab24be4d376c16a540c8886b3e3fe96811fe9e44a006bf36b627bc5d1efc1129b578a7a5b4eecf46f27cb4e1cebd4a448a99cbf5d0999ab83d803433a2e0c6b8d56d3f6d7a118ac91d77f3862473fa64e171429e60a85e347dcfec0d1d5f443b5e434cb2b853ec3b5354c7a3842cf4907c6ab3943bb4cd8a92f45e6bbf98a024c5de6f3ec7e0fa3db7299794d201c4ed3a3968aa6d6f00f34e9d9ecc4f644ebd357faebeba4d16b1f09bc3a1eedf9ac0cee0dd99e7d40e20168b6d3ef
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133088);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2020-1601");
  script_xref(name:"JSA", value:"JSA10980");
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Junos OS: pccd DoS (JSA10980)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a vulnerability in the
path computational element protocol daemon (pccd) process. An unauthenticated, remote attacker can exploit this issue,
by sending malformed Path Computation Element Protocol (PCEP) packets to a Junos OS device serving as a Path Computation
Client (PCC) in a PCEP environment in order to cause the pccd process to crash and generate a core file, thereby
causing a Denial of Service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10980");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10980.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item('Host/Juniper/model');

fixes = make_array();

if ( model =~ '^SRX')
  fixes['15.1X49'] = '15.1X49-D180';

if (ver =~ "^17.2R([0-1])([^0-9]|$)")
  fixes['17.2'] = '17.2R1-S9';
else
  fixes['17.2'] = '17.2R3-S2';

fixes['15.1F'] = '15.1F6-S13';
fixes['15.1R'] = '15.1R7-S4';
# 15.1X53 versions prior to 15.1X53-D238, 15.1X53-D496, 15.1X53-D592;
fixes['15.1X53'] = '15.1X53-D238';
fixes['16.1'] = '16.1R7-S4';
fixes['16.2'] = '16.2R2-S9';
fixes['17.1'] = '17.1R2-S11';
fixes['17.3'] = '17.3R3-S3';
fixes['17.4'] = '17.4R2-S2';
fixes['18.1'] = '18.1R3-S2';
fixes['18.2X75'] = '18.2X75-D40';
fixes['18.2'] = '18.2R2-S6';
fixes['18.3'] = '18.3R2';
fixes['18.4'] = '18.4R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set protocols pcep pce .* destination-ipv4-address";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
