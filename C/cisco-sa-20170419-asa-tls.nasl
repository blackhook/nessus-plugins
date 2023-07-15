#TRUSTED 75b885debbec8cfaad3e447686cd2d7eba7676e3d142eea672d0ff12cf7dc27fca7c7d02cc4c3b4f8e31dd65bdf2a198249a152347684783264d42d061c2f3f0a8e28c7983cf050d43523b89afa83ea07981f5a20228b01e0ee8bcb559fd3125fa5276ae763489d1c163a6dfa051885ec911fb9fc9eb1396a25f23c4c5cfa67863c143637cf3c2ed92594a48e9e52330960b20fe6c580437b35f3218e097220c2d137220c4c6126678b292dec1e5f4645ae2e8ff1c0071a687035acfbd15d14aaee47d8cbb242b9efabf1366ed7bf1c66148bd9318cca9049182cb131ec8fd1a9d892e1d2b04c8dbcf3be0616fa5f1b014645c42961be80fb5365b4dcb53b1fa93fe7e7e00bd11a861a0b4ba84d82384a5f288074eb579a34125aeebab9299ae9cd5524e159057a62c46df41f56f14244bc1e2b76a6d0cc78c5d7058ee8fff0759ff4e0493dc03d5ebaf4de81021ac06dccd1693e8f42f4f6bd3dad5638f8d07422c0dc7ed0d966196074c3f0cedff9d77155a3eb77e7a857b5ecb1dde45bfc9318de25458b8c05d28d1f4e9caab68ea4bd45073a28e9c104b6c13cb125e5d7cb6122af7f46a771596b46e1f05b7dd4f507a08ff302561205ba7327cd30727455eb70fbef6316c1ed4d5a02f75021ac65487e2450f64c33db86ab66c0ee2f33a383b17cff2c1cd49d9cd6f8ee3b26b8888aaf274b9bd75363dd5555314f9c996
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99667);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6608");
  script_bugtraq_id(97937);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv48243");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-tls");

  script_name(english:"Cisco ASA Software SSL / TLS Packet Handling DoS (cisco-sa-20170419-asa-tls)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the Secure
Sockets Layer (SSL) and Transport Layer Security (TLS) code due to
improper parsing of crafted SSL or TLS packets. An unauthenticated,
remote attacker can exploit this, via specially crafted packets, to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-tls
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?262b831a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv48243");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-tls.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^1000V' && # 1000V
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCuv48243';

if (version =~ "^8\.4[^0-9]" && check_asa_release(version:version, patched:"8.4(7.31)"))
  fixed_ver = "8.4(7.31)";
else if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7)";
else if (version =~ "^9\.0[^0-9]" && check_asa_release(version:version, patched:"9.0(4.39)"))
  fixed_ver = "9.0(4.39)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7)"))
  fixed_ver = "9.1(7)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.6)"))
  fixed_ver = "9.2(4.6)";
else if (version =~ "^9\.3[^0-9]" && check_asa_release(version:version, patched:"9.3(3.8)"))
  fixed_ver = "9.3(3.8)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(2)"))
  fixed_ver = "9.4(2)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(2)"))
  fixed_ver = "9.5(2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show asp table socket | include SSL", "show asp table socket | include SSL");

  if (check_cisco_result(buf))
  {
    if (
      ("SSL" >< buf)
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because it is not configured to process SSL or TLS packets");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show asp table socket | include SSL")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
