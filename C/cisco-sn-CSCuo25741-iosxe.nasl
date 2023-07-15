#TRUSTED 674ce80078145ef0f7173b631c7fea93d04b334459b92404d7794c98e32d89f29cbd1b8ca1382f186c3d2e48c54e8ba42179a1f5fe427e4cb0f77efd9a73db28676779fdfe677cdaa4fb4821c5361648d8349464cf6546ccb03cd279dd1f7982d1d1c9ae24e25f95c817475e778cebe6b3de7fbfe89735eb2e0d1253ca0bbf1344ce8c7bca9eb7aff7af4f10355fe531473650bc633910aff4f123d5a8ce87703bb86b20779baebb417a9d27af5d2991243d4fc439a352d41c29e7495081b409c77de56c2790838b5ade4683c35812174afa5e0987aad24834edf294d78bad12146eed34eac3717d4acef41823269b62217dc97b0ee66ba5a3cc8861d3e478513bd52df1aa60143118bfdd39c76efa346a7ff00b14223b5099f28d1c50e98b96b88cee495d3d168628d9e39d70a6b23a17f2d2a757179d28bc7deac8fa6cc209c4396c7868997bf2dd835ddfef61d3527ca9791dbddb8a8cbe37019651d866ba683c122d3972463f154d5d3a5e493f11a1a5ef7a37e3191e3077aa08af8f7a4d45a69ef185f3040fc015c4a16bb42a808b0f490a29ad5f818d284e19562acb764c1d9d5b1977b3aff63968a79338c64c4338fb6e54986b87eb9b34a0a9b7c859421505c28bb1a484966633f27a8a735db33102de34b529722d22c2c5d5777e9bbb1c234241bb5812e4f9d20c890fd45f43ea92ef41f08cc8300a21f3635fe6de
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82588);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0640");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo25741");

  script_name(english:"Cisco IOS XE Fragmented Packet DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the high-speed logging (HSL)
feature due to improper processing of fragmented IP packets. An
unauthenticated, remote attacker, by sending a large number of
oversized packets, can exploit this to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo25741");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo25741
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.0S") flag++;
if (version == "3.11.0S") flag++;

# CVRF
if (version == "3.10.0Sa") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;
if (version == "3.7.0S")   flag++;
if (version == "3.7.1S")   flag++;
if (version == "3.7.2S")   flag++;
if (version == "3.7.3S")   flag++;
if (version == "3.7.4S")   flag++;
if (version == "3.7.5S")   flag++;
if (version == "3.7.6S")   flag++;
if (version == "3.7.7S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.4($|[^0-9])") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ip nat inside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat outside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat (inside|outside) source ", string:buf)) &&
      !(preg(multiline:TRUE, pattern:"^no ip nat ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo25741' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
