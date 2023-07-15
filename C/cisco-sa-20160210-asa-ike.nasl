#TRUSTED 36a32d7b7f4bb559167dc56474d265ef327247054fa0c9b312691a6334bc535205dc807291638c66d1ab62d4fb640dccf4e1d73772ca65b06e8e716718f1c6a4ef0946b094cefccaeba3bab6c8e10438015f01884ee44fe50f222f47d4f6a15e25c43d0b222efca9343f77529cad31ca44924321d552762230795f89f6e97b2047b29eaa78354d07cd411fb37199448d2a4337c2feb7be523ab17be3138039bb767368de473a91940f30154f34093ce11339df44de8b0a536c004c4959392ecce9d16234254b13abf41d529d77b1b18e36005d2f1e79d10267e70957b4c60724ce6c23e5d5d2fa0b24ece57320ecd6cbecddce6a322e749fe24dd591d52b0df3c28ad8713aa2bd2b9cab082d4e708ca773f62189b17f579ba8ed2591a5aca7593d16a1b38c3b0ab2a2a570db44ee480b520fae60a5566dc0adae633e3eb405a8fd2fa9bde2274c68027a37fc126c079b6aef0ec2ee3daac788c6c7b7200c77805b494edb56dc8d01f575c4647bc9abd42e00a25297d96108805764426992af456fadd512caa1c6127c1d0f7a688aa280d72d1a26cd427159707c0f4ea047ec622e1ab3074e5c61578ff0d936931aa93120aaabe8db30b46affde84bcfa3061e4d07a6cf1384513ab8dec5a187e5896021d058957ed3ffd82521ad2ec8b4752c28f47d73139b4141a02bf45ac84d74a65d574caefaa8307b96f3d17d030787852
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88713);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/26");

  script_cve_id("CVE-2016-1287");
  script_bugtraq_id(83161);
  script_xref(name:"CERT", value:"327976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux29978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux42019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160210-asa-ike");

  script_name(english:"Cisco ASA Software IKEv1 and IKEv2 UDP Packet Handling RCE (cisco-sa-20160210-asa-ike)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a remote
code execution vulnerability due to an overflow condition in the
Internet Key Exchange (IKE) implementation. An unauthenticated, remote
attacker can exploit this, via specially crafted UDP packets, to cause
a denial of service or the execution of arbitrary code. Note that only
systems configured in routed firewall mode and single / multiple
context mode are affected.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafc4e71");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20160210-asa-ike.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1287");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

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
include("ccf.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'                  &&
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 1000V 9300 3000 or ASAv");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";

cbi = "CSCux29978 and CSCux42019";

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

if (ver =~ "^7\.2[^0-9]" || ver =~ "^8\.3[^0-9]" || ver =~ "^8\.6[^0-9]")
{
  temp_flag++;
  fixed_ver = "9.1(6.11)";
}
else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.59)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.59)";
}
else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.30)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.30)";
}
else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.18)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.38)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.38)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.11)"))
{
  temp_flag++;
  fixed_ver = "9.1(6.11)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.5)"))
{
  temp_flag++;
  fixed_ver = "9.2(4.5)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.7)"))
{
  temp_flag++;
  fixed_ver = "9.3(3.7)";
}
else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(2.4)"))
{
  temp_flag++;
  fixed_ver = "9.4(2.4)";
}
else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(2.2)"))
{
  temp_flag++;
  fixed_ver = "9.5(2.2)";
}

# Need to check that failover is enabled
# as well as the failover ipsec feature
if (local_check && temp_flag)
{
  temp_flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config",
    "show running-config"
  );
  # Output for vuln config will be like:
  # crypto map <some map name> interface <some interface name>
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"crypto map [^\s]+ interface [^\s]+", string:buf))
        temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug IDs     : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
