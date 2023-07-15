#TRUSTED 00c13e4f00b00529498448f0ace186a949513f50fbcc0882020559dd81e0f719c386174322338884e8cd6b74a9eae802cf3e7787a41f4a954b856fc17d089ae5e4d3288240ee429bb7c15e9198f7eaec1681afc6dbde27343d973d4764603e664e8d1bc5b3c8dca6476b71847dcffc9c39b913eb4ad8b6be8caa1a72ce1f90d9bb1596f71edd77db9b5d862bd40fc1259f23c78fed0a3b7c0513ca51a837a5acba8d19a6b9493c5bf3755901f052b4ca24b06f7c317cb4dfe4497f62086e89745ba2cbc5a7e80c80a33498df1d55ecc36a295726a805cbb1e4358062e9a1052519838fcf49395a8ffb3c6645b91483d5775a32907949bdb90b6b7f3d48fe59fb29f47fc8e4f5eb140293aa3234f0d0b3593e97394f71ee4c22c48cab7c6930cf1459dbe26eb6615efdcb56f34376d664364cf6f6d43fa2885e3e29fb85bfd4509467937640d0c6b91588b28f6be189ed197df98326c9c71fb7300c4095b694bfbd757ddd3917d037ec6c4c8024e1f5e4acd736e83a3f7a97b4948ad89af4b744a904052148d9cf23628c5d27a9ee90bdf119d6c8ef9ca583d4018e15d828f5e8b51f04b0e5b016fbb1e6850a091ff71571eb5524d7200596fb009a3dd7d5ff34130e0b72c9754a5234346c3947222f15b62d15752e0870ba457e75cc3e191423bc2213fac056e9add66dba0721c6012f217333782771f7a685e4ef81665ab40a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91962);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-1295");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo65775");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160115-asa");

  script_name(english:"Cisco ASA AnyConnect Client Authentication Attempt Handling Information Disclosure (cisco-sa-20160115-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software running on the remote device is
affected by an information disclosure vulnerability due to a failure
to protect sensitive data during a Cisco AnyConnect client
authentication attempt. An unauthenticated, remote attacker can
exploit this, by attempting to authenticate to the Cisco ASA with
AnyConnect, to disclose sensitive data, including the ASA software
version

Note that the SSL VPN feature must be enabled for the device to be
affected by this vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160115-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?408d7839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo65775.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;

if (ver =~ "^8\.4[^0-9]")
  fixed_ver = "Refer to vendor.";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.100)"))
  fixed_ver = "9.1(6.100)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.11)"))
  fixed_ver = "9.2(4.11)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(1.99)"))
  fixed_ver = "9.3(1.99)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(0.109)"))
  fixed_ver = "9.4(0.109)";
if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

# Check if SSL VPN (WebVPN) feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
