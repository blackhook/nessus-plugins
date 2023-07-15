#TRUSTED 483bd8ba112f59c46eebf6c8699791e2b84ce2f3a88e6682d73955439c5a4a1806783ad361f7256cdc811e5227dd43f782ed1c5ef117ccb489f63b154a90b062d4466256c59668de51486cbd72acfc358a5e4ea43bd7f843b64417291b7f522d8f5fa8977427529e24a171b13965c6995d19dbb097d81de210350e9e393bc87bb269f5f9c72bd310370b8bc026d0fd8d029593d032256ffad2d4af5b93f89ece97a07e0a421229f501c39f6f038acf36d0d84decdeec00004b68051ee4e2c28b5129c4c0abc7d4c6def2955af34ef55a2b57ce6bafee435b7d8342b5e4614c4e3fd79919a6b2b22f9b2ddae14f524c23fbbc16700089bbd56c930d14be4c4a773eab5f3c8af2c4abefc712a771a6357dd8646f2a12045d4747d6ab156ec469bd662de875289151788afd9c3ef5e574491369817e88daa77ffa8815f4199f867ab0f25dcb53428e106bfe8f64c83f45d7d5c9d31f03d590e177e098eb155ab721bd4c2e717928c02cd4f18c8852b9cb52639b63d80aed68a8d8497ced6b6a5c06775e522d9c9352cdac079cfbc9365df8b8c74f89b6cbe59bb7e7efe263d69082852c10af0082882410ed29b4127ad68ef1e83ab795d1567a3a92ea19d448796bea56244293a192231eaf6d2eb8455890314ac3cef8508a01de1e35b6975c5be2f91215bfbc054946e9812b3580803a47396509007cf72789d9560a576f902c90
#TRUST-RSA-SHA256 aef49f4b7344c001a0aae6aa27898f756a7ad06e1fadb89d6ed55384f0a243ec5f863f6b6f8eb62be48510fc4450e975d0059a8fa2419e24de27e1ca205963d5d2e4a89ffabafff28ddfbb4c250ab96b4e4190204e92304b3389b28b7e3739f119456c0b942245517930ba79a33423fc3ce902b76ceb3b38af2202e858d0939ab4fc91fea1a7da8993298b145262d41cb15b00c6d20f53a16f09f5238a363f34926e7dbabbe18ea601335725b8c30a9b23a7e2822ebb869e0c1b2b2fea0bf5286c50887e15c09f653f9872a611b9ddc138407d29b1c76638a9cadfa4df2ce7a48d14cab27de632692c1776996e2208557a6a2b33d4535fe75471e04b26af92e51d6a0bd9a057c73144c49fa3469e8627a8a693e30cf8cb71d8135b1c22f31b1a98d1c10a2c4119c01eb05414c0e6b0de2da9aef1a290773d7b183ad491444cb486ab88468f680514e0fd10a694873a127641362bd2ae92b34fb3db581a0b647d88a3988471b8d5695a19c9ae51074e94e55d20c2dc47438a40bdcff889ddd671c46a22184c96c70355e7e3cbeb010ca2497e2d62f40df17612ddb6e8ae22359c7d1636118674a023a7ac023e96adcd6396dcafb2b7d7542fb324cb99218f967f7837d6bee46597e9678b06c8589809edb5b775f07da5b259bf83eff83d5448fc71c6bbd12c18aef7434286ab4fccbd734e86456ba5d626afbf4484d3311008a6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78750);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur23709");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-poodle");

  script_name(english:"SSLv3 Padding Oracle On Downgraded Legacy Encryption in Cisco ASA Software (cisco-sa-20141015-poodle) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a man-in-the-middle (MitM)
information disclosure vulnerability known as POODLE.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by a man-in-the-middle (MitM)
information disclosure vulnerability known as POODLE. The
vulnerability is due to the way SSL 3.0 handles padding bytes when
decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. A MitM attacker can decrypt a selected byte of a
cipher text in as few as 256 tries if they are able to force a victim
application to repeatedly send the same data over newly created SSL
3.0 connections.

Note that all versions of ASA are affected; however, the workaround
does not work for versions 8.0.x, 8.1.x, 9.0.x, and 9.1(1)x. Please
refer to the advisory or contact the vendor for possible solutions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-poodle
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7453d3be");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur23709");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround by disabling SSLv3 referenced in the Cisco bug ID
CSCur23709, or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

flag = 0;
override = 0;
fixed_ver = "";
report = "";


# #################################################
# CSCur23709
# #################################################
cbi = "CSCur23709";
flag = 0;
sp_flag = 0;

# Vulnerable version information pulled from cisco-sa-20141008-asa
if (ver =~ "^7[^0-9]")
  flag++;

else if (ver =~ "^8\.0[^0-9]")
  sp_flag++;

else if (ver =~ "^8\.1[^0-9]")
  sp_flag++;

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.55)"))
  flag++;

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.43)"))
  flag++;

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.26)"))
  flag++;

else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.23)"))
  flag++;

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.16)"))
  flag++;

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.15)"))
  flag++;

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.26)"))
  sp_flag++;

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.21)"))
  flag++;

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3)"))
  flag++;

else if (ver =~ "^9\.3\([01][^0-9]" && check_asa_release(version:ver, patched:"9.3(1.1)"))
  flag++;

else if (ver =~ "^9\.3\(2[^0-9]" && check_asa_release(version:ver, patched:"9.3(2.2)"))
  flag++;

if (flag)
{
  flag = 0;
  # Check for the workaround
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_all_ssl", "show run all ssl");
  if (check_cisco_result(buf))
  {
    # Both the server and the client need to be configured.
    if (!preg(multiline:TRUE, pattern:"ssl server-version tlsv1", string:buf)) flag++;
    if (!preg(multiline:TRUE, pattern:"ssl client-version tlsv1-only", string:buf)) flag++;
  }
  else if (cisco_needs_enable(buf)) {flag = 1; override = 1;}
}

if (flag || sp_flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
