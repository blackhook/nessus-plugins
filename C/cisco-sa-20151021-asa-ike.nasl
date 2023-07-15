#TRUSTED 48a499ee6e087c4cf60b1dd8500725e6eeffb9ad755e1b535f07b72e903945752019c2a064bc1c9a0b1d9f9c0994572920cd909834cf8dfa9b4409225fbbf659f26a489f631029161c8b1c26da23fb48769e914c6206f0093de1955cbd559053cc8d60d220df95a080faaa597e707a848523a8c2e9ad67e97e1a9bdd4988debc29d40b6049436e3544fa73100ad6ea85a014d46390086c2e8e5d238c82e96bdf59017c9fafc4fe8335af65e64da51f6f71a9a3debacfde824b74f0dbaf4269cb1fa44f16ce1f4ee6a34401cc4295228beae89b835feb05aea2db8f6535692d8245c85ef6dff8c7124a3430f39a5a4c0d0a64ce6eb52785d4e0523f9d3b1097927c8ba3a705978260f762122dfcdd7b91032186e008affc632bb8905da632055af145dfcdd54da6a94332c5a14792c49b3c3ce1380593ac803e6396384b5a8a48655366d7183da712bf381f8cbe672587b97bddc9cec6a2eb3e9b293fb4b41282370a4d69f443a655c8488fac3e4b4ba4f04fad842c4825c505f34777aaedcbf0274bbc179b1b88b8fcec3ba2acaebe8c75bb443bf0dd3e433521e8adf8be208165775b19397532cf4ee8b85044b3a78c12aa709f4635f44a269ca84037491e5d183be62e7b9673d4194b4359226865be5bf736c9ef663fa200f09741607416902e571935527747ceb89533ee4a87793de75e4b0d674cdd0fb545dd59ff54ebd2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93531);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-6327");
  script_bugtraq_id(77262);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus94026");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151021-asa-ike");

  script_name(english:"Cisco ASA IKEv1 ISAKMP Packet Handling DoS (cisco-sa-20151021-asa-ike)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper handling of Internet Security
Association and Key Management Protocol (ISAKMP) packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted ISAKMP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edb2acbc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus94026");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus94026.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

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
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers
# Cisco ASA 1000V Cloud Firewall
# Cisco Adaptive Security Virtual Appliance (ASAv)

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'                  &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V or ASAv");

fixed_ver = NULL;

if (ver =~ "^7\.2[^0-9]")
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.58)"))
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.3[^0-9]")
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.29)"))
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.5[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.6[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.17)"))
  fixed_ver = "8.7(1.17)";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.8)"))
  fixed_ver = "9.1(6.8)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
  fixed_ver = "9.3(3)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if ASA is configured to terminate IKEv1 VPN connections
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface", "show running-config crypto map | include interface");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"crypto map [^\s]+ interface [^\s]+", string:buf))
    {
      # Secondary check to ensure IKEv1 is enabled
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto ikev1", "show running-config crypto ikev1");
      if (check_cisco_result(buf2))
      {
        if ("crypto ikev1 enable outside" >< buf2)
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the system is not configured to terminate IKEv1 VPN connections");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus94026' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
