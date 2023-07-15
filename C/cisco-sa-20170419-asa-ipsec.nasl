#TRUSTED 7e8f21f3b3b69b9c57d7b4451d6e3045a70f877894c5f3925843f3c8d50ac6a0a4a94f977fad978fba45c57511d476fce059c1e40e7588c3a61ea320e41f978864124de6779c4fc7fcb5257c6defedf5c9cea699b961ca0a89bd5de15367f598e79f4ca437d1989e7f3aac1c7960c50d0d3cff58478172d1ba95f048ad4d33aaeb8bc8e55c78d319c4ffa92dd69dfb8c3cf74b520264d04091c33ed0aad52d70cc8746b83fc541eee2b61d1160cbec30280322c0b71c83bd9b95032f55ef27da2b01efff2b4ef5b3fafdefcb57662507d6cabbc16f8dd98fe174a49315cfcb92235d7eac210b2eb9ef1407912f671ce1b07a1ff81a78bf5ffa5ed82ce664cea21f964ca6be62cdb310e69e09d508c4cfe8db678525cd384688a5c50d014dd64a8e16a4e9e3d764e2dbab7f57be5ec889c6b31a42579f305fe78d942f292b01798094bddbdfeb6536756f4fd333540ff81eb12b2d3a33ef1cfa729a0053727f4dd5352cd9bded09f538c1d07051eaed6cd723ede504361b2f17e2ca58388c75d518b75ef2d7b5543553c99f245b0c7c58fc3f4afd13d15c8290f2f2ae16983b593727215d94b5b542d1d9a67a4b5b013ffeb185bc41d2d762d1e3e950a7064b8bc76ff89d3874167e5da5996debd41aaceee6acffb27eba7797bda8fa991b44c6c7c37c26bca669eea3033399823f79145ede32e64833a886e9ece4c06e4e829f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99666);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6609");
  script_bugtraq_id(97936);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun16158");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-ipsec");

  script_name(english:"Cisco ASA Software IPsec Packet Handling DoS (cisco-sa-20170419-asa-ipsec)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the IPsec
code due to improper parsing of malformed IPsec packets. An
authenticated, remote attacker can exploit this, via specially crafted
IPsec packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-ipsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ea5056");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun16158");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-ipsec.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6609");

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

cbi = 'CSCun16158';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.8)"))
  fixed_ver = "9.1(7.8)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.15)"))
  fixed_ver = "9.2(4.15)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3.2)"))
  fixed_ver = "9.5(3.2)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2)"))
  fixed_ver = "9.6(2)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface", "show running-config crypto map | include interface");

  if (check_cisco_result(buf))
  {
    if (
      ("crypto map" >< buf)
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because it is not configured to terminate IPsec VPN connections");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config crypto map | include interface")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
