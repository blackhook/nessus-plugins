#TRUSTED 044ac291122ca52d32fd67fb093824b6d59fe201209588e71faefdcaf2a758704fd102d2955232ecd8ef5169e03eadd7f3ac119459b6cc99ae2847b0e60a52dbbc40bae4e85ef83d443d715d00d8c70a5f325168a95e2eb949bfc24c636faeb045de17dba21d336bfb668320304b4ce202e32c94def456488f1cce173e93d150fdf789fa9356e19e578202ede1698db2569f7d5e83577d7bcdca1291d243a8cff3b0fb8a74e4e08365d4a0097571214eb078f43c594102c00c6acd034e4e17e7e93ca3626e459f69cf0d59dad4113b59de38ebac619d303220400cd68967b7e2377ea4274c9e0a2d4e0fe135cacda4b244868caed9019d3a89cd3290e67751d46d14f2df3f23a0e7fa807a6685d1c9ab86bb44cbaebb37c54c3313333cf22a640be1eae4820927259977ff65d4113e5221fa09275984cef73d6e8f6508d82471e8bac0208cf1b07512e3dee47367c02840ebd189366487cf76a19994f1a3d4a9d2486148311f2d32aa3989fc0f59118d85669ecb4c2849661a9e3c42d3506a371bb8cc119935273b1336fff707d038d269ef6f3fcb87fa404539f4bc82aa9781f7e6e97a6f76e8d481a6238d70236a4c3c3a518e7706531b62321ee0e5a84751b04971ef2af545f02465a4f37978eac5b6e6c71297b5398eef605e5268caadf99d7190fab72c8caccc644d6808df9c53dedbe47614944e0d64ed00a83c3e6b95
#TRUST-RSA-SHA256 9dacb87b8a0cee6594be8f29e09e246e068977aa9f5b765148128a0cba662e44e2468f4b1d630f63ba9b49c997f8cbfab784aa1aed3e5c4d77de048468720908a53030790d511037b5ee25bd28bb6e4dec4875003c7c790b7a3eb82173ec06a0f63d83cacfed9fd54cdf33821e870ca659e913a99f66f88a64db7bbb6920ddadf6b6a8c756119a34363900fbe13bebbeeb99e176f380076b19fb975611602f6f714dee1f16452e359b600453dc844c0dd4b89e36746f9e59a75ab963d265148efb22f79af34b1d8eb66b0487658dc5c215563e7bcdfade108438848d8f4f7f2bd87218d2a1c4a44a9643f597b44e3690c0bdf639e0d662d1bf222f9d18e5613dd850f90296b2d2b51742ff62349c351ec97cfd08fba4f280dcf4fdc38ec1fd8c39616f12f52ff9954fe2069c4328f4743a86d06aa2bfd7b6199ed662e6e207611e9b564254ff5836765c40854e33f8089a0acfa9d4eacb20d781e4e2894058ebf75a5f877c40d8a1d11112049f4260d4f68a9de190269225d11167f281f4b0fd8dc7db8c61bfa00b0410061f4037a4b33c6ecba6feb858c8cd9a2ae1ee7c8b7f2b9a74fd0eb66858b7f680e509c7f4c0e0fcf8f09d917d7ee31bc38a39e32df34a96208fdaf07642c29cfd7d9c1c780d47a4fd1f86ed76496c92f88ebd0566e2ecc650656ca2e1142104e9c0301328b2e6e149439244d2c7e9f8184d20b591c3
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(69376);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug34469");
  script_xref(name:"IAVA", value:"2013-A-0157-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco ASA (cisco-sa-20130801-lsaospf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link
State Advertisement (LSA) database.  This vulnerability could be
exploited by injecting specially crafted OSPF packets.  Successful
exploitation could allow an unauthenticated attacker to manipulate
or disrupt the flow of network traffic through the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a643e96");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report_extras = "";

asa = get_kb_item_or_exit('Host/Cisco/ASA');
ver = extract_asa_version(asa);
if (isnull(ver))
  audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = "";

if (
  ver =~ "^7\." ||
  ver =~ "^8\.0[^0-9]" ||
  ver =~ "^8\.1[^0-9]" ||
  ver =~ "^8\.2[^0-9]" ||
  ver =~ "^8\.3[^0-9]")
{
  flag++;
  fixed_ver = "8.4(6)5";
}

if (
  ver =~ "^8\.4[^0-9]" &&
  check_asa_release(version:ver, patched:"8.4(6)5"))
{
  flag++;
  fixed_ver = "8.4(6)5";
}

if (
  ver =~ "^8\.5[^0-9]" ||
  ver =~ "^8\.6[^0-9]")
{
  flag++;
  fixed_ver = "9.0(3)";
}

if (
  ver =~ "^9\.0[^0-9]" &&
  check_asa_release(version:ver, patched:"9.0(3)"))
{
  flag++;
  fixed_ver = "9.0(3)";
}

if (
  ver =~ "^9\.1[^0-9]" &&
  check_asa_release(version:ver, patched:"9.1(2)5"))
{
  flag++;
  fixed_ver = "9.1(2)5";
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ospf_interface", "show ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
