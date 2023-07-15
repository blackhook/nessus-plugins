#TRUSTED 46c3c84b86eb8467863cdf6bab595f7bed7f2171cd16444099b2c6f9d23d45b62059a18ae39953c5b9d8537c97a62faf3358fd842218abd84ad26e4ea50ecd6f63e22d9955e81809629cfd8d14709d84383620347c91a6c85183963e66373ad7a9c77305591fb899477fab781693458391428a6f516bb3cdd1b4a2ef56b1b20fc38a1231c07c801942947f57fe1cb67046842c5542d2d43be80f3ce32f4a9ea6751a4b6d21fdb79a17fe65a4847e2115d4618eabe72ba72b64653a4dab0e66898ff289a81425f46f22e2eaa7b848beee3d5d4ecd17398f8db2aebf8a21adb4bff484de0222cf42e1b81ea6fa7160b0c87ac438631ea4e1fd767fa830d9f18c9d70172046411f34739df16f24e80d3c4624a283c5268c15150e1b3b866834c05d596b3d209ceac6bcc54a39c6363d889befcb97c0d41f9401a59255e6d5d6bfaf855b9e5c4b940fd2bf210bbf93567640fe9aa80b2d46ecf0fece1174de8d359dd32798003b80703ae46c980c7adc0d34722e40d6a2411fb238d41a05e39e456828804f7ca591474df95fd6e646ad2764af11a5737861d64107028f55f6204e200829067aa42a3fb0f514c280b52aa04b96e71083345282027fd1e7109425fcd2299dd4cdecd40837ec207eec848019a27fe40ca33c50e3fc4b120bd9519ef3d11996e92aaf0f48aeece43e26ed3b67a9c5fc3d9cdb1ae7944e691c9268ed7dc2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99371);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3878");
  script_bugtraq_id(96927);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46778");
  script_xref(name:"IAVA", value:"2017-A-0096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170315-nss");

  script_name(english:"Cisco NX-OS Telnet Packet Header Handling Remote DoS (cisco-sa-20170315-nss)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the Telnet remote login functionality due to improper
validation of Telnet packet headers. An unauthenticated, remote
attacker can exploit this, via specially crafted Telnet packets, to
cause the Telnet process to restart.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-nss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea47371");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
cbid = FALSE;

########################################
# Model 9k
########################################
if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "7.0(3)I3(0.170)") flag = TRUE;
  cbid = "CSCux46778";
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

# Check for telnet feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?feature telnet", string:buf))
    flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
