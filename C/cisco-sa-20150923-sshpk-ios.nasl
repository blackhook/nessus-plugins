#TRUSTED 999db282c6dca4e64d2d0c2b45377aa4a8c84079c774c7f12a948afd94105a52da0374cdf1b0a8200cf1f4f58e6f2c21e27d66a4c87ffb271e0f8dfb5a9335725c1fc036774fedbdc1b9cbacd785b8e6d551ee540ceb434b82c12d0d7037f8c7a2053ebef33c7bc7b1e2bd2586ec54103b3fc53709f9b60ef3f395bdf5461c25623dbcfdfab2de7303afcea638dc44309147495ee27cf77d307270600b08f94b190e6e2acf82f9e88ea28819e791644eab0ee5cbb1423fd068aef5e64ec38ab5f7829e46197992fe356d9ddc4b0efb4440674e8e0ab21b1d5976b076c5906862ebba7cc79640017e4a12f8cee68407f2904e4ea3fdc5759cfc84be76636a821159063843a870fb815d866cc85bfaa789e149bf19eb8815f7d304eeedd29033f86f72cd040104a6f297e9bd3b5f9e4c9cbd098944ea4b342d72791c025b25a841711c3371ed8d9efd57f115fc08529a8320ca8d3291def48160156bcff2f1580fad1271747a8aea4ca0d333f4c6d41ae1dda1be5ec8248404faacd8af51f3227f67d902eef44656e15039ed24fb03c52095fcaf6fce5f6eb654a938fcad3cc3b5ff032db2a1619c765f54d91f53cdb6d70213f44421078d0604b3d9a72340df6f56e7ee03f09e051414b36da35be745a37fcb9a3874c00ab94d9be39fcbeb43501fcf6cc4797cfe16e2106766dfe8d280b28186e5dca300a6ddc8245597947dce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description){

  script_id(86249);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2015-6280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus73013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-sshpk");

  script_name(english:"Cisco IOS SSHv2 RSA-Based User Authentication Bypass (CSCus73013)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is missing a vendor-supplied security
patch, and is configured for SSHv2 RSA-based user authentication. It
is, therefore, affected by a flaw in the SSHv2 protocol implementation
of the public key authentication method. An unauthenticated, remote
attacker can exploit this, via a crafted private key, to bypass
authentication mechanisms. In order to exploit this vulnerability an
attacker must know a valid username configured for RSA-based user
authentication and the public key configured for that user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2660861");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus73013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6280");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2020 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =="15.2(1)SY") flag++;
if (ver =="15.2(1)SY0a") flag++;
if (ver =="15.2(2)E") flag++;
if (ver =="15.2(2)E1") flag++;
if (ver =="15.2(2)E2") flag++;
if (ver =="15.2(2)EA1") flag++;
if (ver =="15.2(2a)E1") flag++;
if (ver =="15.2(2a)E2") flag++;
if (ver =="15.2(3)E") flag++;
if (ver =="15.2(3)EA") flag++;
if (ver =="15.2(3a)E") flag++;
if (ver =="15.3(3)M1") flag++;
if (ver =="15.3(3)M2") flag++;
if (ver =="15.3(3)M3") flag++;
if (ver =="15.3(3)M4") flag++;
if (ver =="15.3(3)M5") flag++;
if (ver =="15.3(3)S") flag++;
if (ver =="15.3(3)S1") flag++;
if (ver =="15.3(3)S1a") flag++;
if (ver =="15.3(3)S2") flag++;
if (ver =="15.3(3)S3") flag++;
if (ver =="15.3(3)S4") flag++;
if (ver =="15.3(3)S5") flag++;
if (ver =="15.4(1)CG") flag++;
if (ver =="15.4(1)CG1") flag++;
if (ver =="15.4(1)S") flag++;
if (ver =="15.4(1)S1") flag++;
if (ver =="15.4(1)S2") flag++;
if (ver =="15.4(1)S3") flag++;
if (ver =="15.4(1)T") flag++;
if (ver =="15.4(1)T1") flag++;
if (ver =="15.4(1)T2") flag++;
if (ver =="15.4(1)T3") flag++;
if (ver =="15.4(2)CG") flag++;
if (ver =="15.4(2)S") flag++;
if (ver =="15.4(2)S1") flag++;
if (ver =="15.4(2)S2") flag++;
if (ver =="15.4(2)T") flag++;
if (ver =="15.4(2)T1") flag++;
if (ver =="15.4(2)T2") flag++;
if (ver =="15.4(3)M") flag++;
if (ver =="15.4(3)M1") flag++;
if (ver =="15.4(3)M2") flag++;
if (ver =="15.4(3)S") flag++;
if (ver =="15.4(3)S1") flag++;
if (ver =="15.4(3)S2") flag++;
if (ver =="15.5(1)S") flag++;
if (ver =="15.5(1)T") flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-begin-ip-ssh-pubkey-chain", "show running-config | begin ip ssh pubkey-chain");
  if (check_cisco_result(buf))
  {
    if (
      "ip ssh pubkey-chain" >< buf &&
      "username" >< buf
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus73013' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
