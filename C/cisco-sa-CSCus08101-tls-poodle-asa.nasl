#TRUSTED 0c5b26581f6aea78caf63feeb7638e9cb4a4c1d637d563ecbe16db7623f0b28274e754672162bfa1f9baab6f1414e9940c8e74dad1157ce4d3e6dcfa46f08b5e45adce857037fe0a110e5ac9617937a770ed5965faaa44590853de64a13a9a900b57c5b3b6486d6f621cfd1cfd931eeee9b8ed49272abf80a15cb042045c15c4719cc602b691459e9da7cf6340753242fb1ec67579d2c1cde34f72b95db07848eeee82324211c523ad94bcee3a3b9872535c7a74325f4713696e5369417eacc40c447a56af1c374b1c2b281c0bdcc802bca10d6ac5b006ca38f7e8230b5ad14b329b6f01265c81bc7a3f44edec6a39a5b846826363f7ffb5a4013bc82a50607e743f1963b1e366ad409ff3546c94e64460c372ab7b1a867852c65a15c1d37012c6e7541a4c8afbc975f2b1230603d90468c2de5cd3e5446a81276c9aa9af68c1d206d8fb3cc5f1bc4e787f0d7e705edf3502a9c38e9446b90a572f1151618659081139a6a0848e7876cf8a818b769d21641b938f0c42829257d0b1d95940e69392200a5577ad08c37b141a924d7c8304f56d7d390f58989fc664966e3d1b4ec5f63378738eb3f26b62befe42cddd0b5eebe71789153397bed70a089a77b2684338d5b0caa789fb8cfd0ae43418cc5a2dcd967866dc6ee75e58a3ad71192fe2ec178e65c5746d661fa3e7463082c2809d31616407616a2887d62487cb32087baa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82429);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/09");

  script_xref(name:"CISCO-BUG-ID", value:"CSCus08101");

  script_name(english:"Cisco ASA TLS CBC Information Disclosure (CSCus08101)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Cisco ASA software on the
remote device is affected by an information disclosure vulnerability
due to improper block cipher padding by TLSv1 when using Cipher Block
Chaining (CBC) mode. A remote attacker, via an 'Oracle Padding' side
channel attack, can exploit this vulnerability to gain access to
sensitive information. Note that this is a variation of the POODLE
attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/12/08/poodleagain.html");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus08101");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=36740");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver   = extract_asa_version(asa);

if (isnull(ver))
  audit(AUDIT_FN_FAIL, 'extract_asa_version');

# ASAv shows model == 'v'; ignore here as well.
if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500 or 5500-X');

fixed_ver = NULL;

# Affected version list from advisory
versions = make_list(
  "7.0.0",
  "7.0.1",
  "7.0.1.4",
  "7.0.2",
  "7.0.3",
  "7.0.4",
  "7.0.4.2",
  "7.0.5",
  "7.0.5.12",
  "7.0.6",
  "7.0.6.18",
  "7.0.6.22",
  "7.0.6.26",
  "7.0.6.29",
  "7.0.6.32",
  "7.0.6.4",
  "7.0.6.8",
  "7.0.7",
  "7.0.7.1",
  "7.0.7.12",
  "7.0.7.4",
  "7.0.7.9",
  "7.0.8",
  "7.0.8.12",
  "7.0.8.13",
  "7.0.8.2",
  "7.0.8.8",
  "7.1.0",
  "7.1.2",
  "7.1.2.16",
  "7.1.2.20",
  "7.1.2.24",
  "7.1.2.28",
  "7.1.2.38",
  "7.1.2.42",
  "7.1.2.46",
  "7.1.2.49",
  "7.1.2.53",
  "7.1.2.61",
  "7.1.2.64",
  "7.1.2.72",
  "7.1.2.81",
  "7.2.0",
  "7.2.1",
  "7.2.1.13",
  "7.2.1.19",
  "7.2.1.24",
  "7.2.1.9",
  "7.2.2",
  "7.2.2.10",
  "7.2.2.14",
  "7.2.2.18",
  "7.2.2.19",
  "7.2.2.22",
  "7.2.2.34",
  "7.2.2.6",
  "7.2.3",
  "7.2.3.1",
  "7.2.3.12",
  "7.2.3.16",
  "7.2.4",
  "7.2.4.18",
  "7.2.4.25",
  "7.2.4.27",
  "7.2.4.30",
  "7.2.4.33",
  "7.2.4.6",
  "7.2.4.9",
  "7.2.5",
  "7.2.5.10",
  "7.2.5.12",
  "7.2.5.2",
  "7.2.5.4",
  "7.2.5.7",
  "7.2.5.8",
  "8.0.0",
  "8.0.1.2",
  "8.0.2",
  "8.0.2.11",
  "8.0.2.15",
  "8.0.3",
  "8.0.3.12",
  "8.0.3.19",
  "8.0.3.6",
  "8.0.4",
  "8.0.4.16",
  "8.0.4.23",
  "8.0.4.25",
  "8.0.4.28",
  "8.0.4.3",
  "8.0.4.31",
  "8.0.4.32",
  "8.0.4.33",
  "8.0.4.9",
  "8.0.5",
  "8.0.5.20",
  "8.0.5.23",
  "8.0.5.25",
  "8.0.5.27",
  "8.0.5.28",
  "8.0.5.31",
  "8.1.0",
  "8.1.1",
  "8.1.1.6",
  "8.1.2",
  "8.1.2.13",
  "8.1.2.15",
  "8.1.2.16",
  "8.1.2.19",
  "8.1.2.23",
  "8.1.2.24",
  "8.1.2.49",
  "8.1.2.50",
  "8.1.2.55",
  "8.1.2.56",
  "8.2.0",
  "8.2.0.45",
  "8.2.1",
  "8.2.1.11",
  "8.2.2",
  "8.2.2.10",
  "8.2.2.12",
  "8.2.2.16",
  "8.2.2.17",
  "8.2.2.9",
  "8.2.3",
  "8.2.4",
  "8.2.4.1",
  "8.2.4.4",
  "8.2.5",
  "8.2.5.13",
  "8.2.5.22",
  "8.2.5.26",
  "8.2.5.33",
  "8.2.5.40",
  "8.2.5.41",
  "8.2.5.46",
  "8.2.5.48",
  "8.2.5.50",
  "8.3.0",
  "8.3.1",
  "8.3.1.1",
  "8.3.1.4",
  "8.3.1.6",
  "8.3.2",
  "8.3.2.13",
  "8.3.2.23",
  "8.3.2.25",
  "8.3.2.31",
  "8.3.2.33",
  "8.3.2.34",
  "8.3.2.37",
  "8.3.2.39",
  "8.3.2.4",
  "8.3.2.40",
  "8.3.2.41",
  "8.4.0",
  "8.4.1",
  "8.4.1.11",
  "8.4.1.3",
  "8.4.2",
  "8.4.2.1",
  "8.4.2.8",
  "8.4.3",
  "8.4.3.8",
  "8.4.3.9",
  "8.4.4",
  "8.4.4.1",
  "8.4.4.3",
  "8.4.4.5",
  "8.4.4.9",
  "8.4.5",
  "8.4.5.6",
  "8.4.6",
  "8.4.7",
  "8.4.7.15",
  "8.4.7.22",
  "8.4.7.23",
  "8.4.7.3",
  "8.5.0",
  "8.5.1",
  "8.5.1.1",
  "8.5.1.14",
  "8.5.1.17",
  "8.5.1.18",
  "8.5.1.19",
  "8.5.1.21",
  "8.5.1.6",
  "8.5.1.7",
  "8.6.0",
  "8.6.1",
  "8.6.1",
  "8.6.1.1",
  "8.6.1.10",
  "8.6.1.12",
  "8.6.1.13",
  "8.6.1.14",
  "8.6.1.2",
  "8.6.1.5",
  "8.7.0",
  "8.7.1",
  "8.7.1.1",
  "8.7.1.11",
  "8.7.1.13",
  "8.7.1.3",
  "8.7.1.4",
  "8.7.1.7",
  "8.7.1.8",
  "9.0.0",
  "9.0.1",
  "9.0.2",
  "9.0.2.10",
  "9.0.3",
  "9.0.3.6",
  "9.0.3.8",
  "9.0.4",
  "9.0.4.1",
  "9.0.4.17",
  "9.0.4.20",
  "9.0.4.24",
  "9.0.4.5",
  "9.0.4.7",
  "9.1.0",
  "9.1.1",
  "9.1.1.4",
  "9.1.2",
  "9.1.2.8",
  "9.1.3",
  "9.1.3.2",
  "9.1.4",
  "9.1.4.5",
  "9.1.5",
  "9.1.5",
  "9.1.5.10",
  "9.1.5.12",
  "9.1.5.15",
  "9.1.5.19",
  "9.2.0",
  "9.2.1",
  "9.2.2",
  "9.2.2.4",
  "9.2.2.7",
  "9.2.2.8",
  "9.2.3",
  "9.3.0",
  "9.3.1",
  "9.3.1.1",
  "9.3.2"
);

foreach version (versions)
{
  if (cisco_gen_ver_compare(a:ver, b:version) == 0)
  {
    if (ver =~ "^7\.") fixed_ver = "Refer to the vendor.";
    else if (ver =~ "^8\.[01][^0-9]")
      fixed_ver = "Refer to the vendor.";
    else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.53)"))
      fixed_ver = "8.2(5.53) / 8.2(5.55)";
    else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.43)"))
      fixed_ver = "8.3(2.43)";
    else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.25)"))
      fixed_ver = "8.4(7.25) / 8.4(7.26) / 8.4(7.170)";
    else if (ver =~ "^8\.5[^0-9]")
      fixed_ver = "Refer to vendor.";
    else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.16)"))
      fixed_ver = "8.6(1.16)";
    else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.27)"))
      fixed_ver = "9.0(4.27) / 9.0(4.29)";
    else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.101)"))
      fixed_ver = "9.1(5.101) / 9.1(6)";
    else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.1)"))
      fixed_ver = "9.2(3.1) / 9.2(3.3)";
    else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(2.1)"))
      fixed_ver = "9.3(2.1) / 9.3(2.2) / 9.3(2.99) / 9.3(2.201)";
    break;
  }
}

if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(port:0);
