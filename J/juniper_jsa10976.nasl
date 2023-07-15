#TRUSTED 366b353cd2839999eca70fc1da867d0d9c651a1595259f408d7e68332fb90deffc89a5e99ffcc868db7e4bef384b9ab33cac81201202b0d71ce05d42b98708d7508db92d0f705ea9a83479df826c94142fb4b2c76236ca8a98bbffe4c4f14e780559a20cf631096dbbebe385c876e6e0eb7ca17dd4804f5bdac0f4fa3b2c9d6942ebb5eec66a9151c02549f3e245f99f823c8ff71fa4dfa9463253f8253091f64d8e0b6494a76b072e056ab311d5bd5e96cb5d34741396a0647ebca3c30d4559be0785e59d55495ae8e12d24a04693337843b010d52d20856c780e02ba17d77a41589bea06ea68b00f32d76d67d6285e0395da6324807cddcbb40944be62f4360ed3dcf09c0e261f3d851640006cca5006e000b78cdf644fd7c351a63f362fc0f44be7c82fea820dec85e06d319fa36ec7a026c3103ee46cea1ffbc9e8a6d73ec52ea1f3fa1a3dc664c691eeaf4938113d5221cd879df555ee03002f4fe86938592f158dd6858dfaa8f8d50ea286a392e4e8325f15517aa615c0940ca59eb29e268daa053d180a2352be65e96eadb6d3e53e4cf01d1579cfe68c730657cdbc537bc78ab66b95883d26be8e57ba48b34b48acb2ae845206aebf14ac245e03f6ad7a7751ffdd869af71f32fbd19a3dd5bd927f2796b3f1adf5d96f69fe6533f0b39466b23c9294b35a22f1951571654f71564325e914624f99d13525d90c748848
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130467);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0075");
  script_xref(name:"JSA", value:"JSA10976");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: srxpfe PIM DoS (JSA10976)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability in the srxpfe process on Protocol Independent Multicast (PIM) enabled SRX series devices. An
unauthenticated, remote attacker can exploit this issue, by repeatedly sending crafted PIM messages, to crash the
srxfpe process and cause an FPC reboot, leading to an extended denial of service condition and causing the system to
stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10976");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10976.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0075");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
# SRX Series
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.3X48'] = '12.3X48-D80';
fixes['15.1X49'] = '15.1X49-D160';
fixes['17.3'] = '17.3R3-S7';
fixes['17.4'] = '17.4R2-S8';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R2';
fixes['18.3'] = '18.3R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If PIM is not enabled, audit out.
# https://www.juniper.net/documentation/en_US/junos/topics/topic-map/mcast-pim-understanding.html
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set protocol pim";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as PIM is not enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
