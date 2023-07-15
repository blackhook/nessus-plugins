#TRUSTED 2b81654a62272b678b1959beb9fdbb33f08a797a6ea631650732c9a5175af3d91d7e5a3729d872021db8932e7277a5087bba5aba1aab99f3d6e90eb3e992d03e7ee65cfd56f418f8bd2070fde6fe303d545ffca007e1ce88f1fadd543a77f4b47c426001cdeb3916f92cd6eab84ab3f8d62f3eda1519078c33a41d65339688bb0fa1161261aae5e64afd3ead85c83390be4b2af72977d2cf8435edaaa3e91fc400571f34ced47fe402e38425bf5fbca5765c915658c4d45e86435a06161d00b795068c9434caec728030fffd05106d9d3c84859d23cf8248bbb13b04f18c5eb3a96e3fee9fdd2ee26afee6de02bf1e776ff2860f9aa8f2f25f9296f75e3bcee46db8a60613e19631c2cf29a37ce0000e73cd246e0471dd25553610b22dbf0944a0ef13699f7a8d1c0960bec221fe52db808a54c3a18c300c941a56150aee3b2fe414d90a671156dbcfedd5499c83684a55689b75a33edecbc04f369729f5a25a74482954d65888423ec00666645587bd595b80c7f9e9b2cf64e3207d3f1b11c018096868a5be92d24f216b957424f07b5ad2d763309b3db4e43d0d8f2f553d399287668bf80bd86802ef9df26360149667069dc0c939d52e87bdc6e59edb8adfb016b1d984a68feb5cd944e06de1114681f366ea89e54872e5e3440cc3c48afd48f5e7892aa5649a6918ebfb3b706b0021357d0c1608df51014f25e01ea6b8e3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91759);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2015-6360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux00686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco ASA libsrtp DoS (CSCux00686)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing
vendor-supplied security patches, and it is configured to use the
Phone Proxy feature. It is, therefore, affected by an integer
underflow condition in the Secure Real-Time Transport Protocol (SRTP)
library due to improper validation of certain fields of SRTP packets.
An unauthenticated, remote attacker can exploit this, via specially
crafted SRTP packets, to cause packet decryption to fail, resulting in
a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2658d700");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20160420-libsrtp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;
cbi = "CSCux00686";

# Check for vulnerable versions. Cisco ASA Phone Proxy feature was deprecated in 9.4.1
# 8.0 -> 8.3 do not have an upgrade in the same train. Upgrade these to 8.4(7.31)
if (ver =~ "^8\.[0-3][^0-9]")
{
  fixed_ver = "8.4(7.31)";
}
if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.31)"))
{
  fixed_ver = "8.4(7.31)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(7)"))
{
  fixed_ver = "9.1(7)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.6)"))
{
  fixed_ver = "9.2(4.6)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.8)"))
{
  fixed_ver = "9.3(3.8)";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

# Check if the keyword "phone-proxy" exists in the configuration. If it isn't
#   then the system is not vulnerable.
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-phone-proxy", "show running-config phone-proxy");
  if (check_cisco_result(buf))
  { 
    if (preg(string:buf, pattern:"^phone-proxy [^\s]+", multiline:TRUE)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the phone proxy feature is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
