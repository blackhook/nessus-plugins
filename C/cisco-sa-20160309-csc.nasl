#TRUSTED 056ec9a338ffc9cfdf60d7b71a2202558566900d0f4fce42a07600bda34257806d1a8b347383ec6cb83a9447690c95036440caccc079ff7891f07cfe5c1ad6995ef03f4c1910042e46c4e19de5df3f69025604b4f2a57ecd491b8012a001f6745d1627774ad61a61cde51bc0883c524abc70232cc48dbf4618c54ab7398e8b4810ab3db355ee79ed67cf512ba0be1d3f9495827cd695b4722a4426aa9bc38ee53415f83613fd1a3e48f0ac7298b62528f20a14faabbba33dec6ce8877f5d8cb1d9675fecea15b2cc015a26ecf8e92b20b6efcaee109d4196728e18e3f2b51a942e162d01c3e459915774180d54ebad5ce35493921586b3b4f85c34c7cccb6bcc76b3c905d1a3b7e1e4b0b99023265548524056d8f72d07b483f1da16c2a47d22204d18b2698046cdba477ed76d4bedde6d564bb0302eae89a6b5bf075db29bc2c8fd17d8c5cb931437a22f68cf278c85447ea0b93d649192cf45a4d9a89fb047779540f913e55dfbbbb05cb7186378858d29e0ebe7fb80ad2ab236719c8c1615c92a5ca118ba757da3bd7b1513b12295b8755945f34838b7bcfa451db6a659ada082baafcdf2206017345d37c0e24b1df9faac968a1286493d13e222d216e3163034a4290253312eb1bba386d8f58fec00fe8e0ac2d48bfae39ab5e7a713738295daa91b871cc161ff654d3ee2103d161a5d987687c84592bb7b4b584b348563
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90066);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-1312");
  script_bugtraq_id(84281);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue76147");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160309-csc");

  script_name(english:"Cisco ASA Content Security and Control Security Services Module (CSC-SSM) DoS (cisco-sa-20160309-csc)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a denial
of service vulnerability in the Content Security and Control Security
Services Module (CSC-SSM) due to improper handling of HTTPS packets.
An unauthenticated, remote attacker can exploit this, by sending a 
high rate of HTTPS packets, to exhaust available memory resources,
resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160309-csc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?884fa710");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCue76147.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

model = get_kb_item_or_exit('Host/Cisco/ASA/model');
if (model !~ '^55[0-9]{2}($|[^0-9])')
  audit(AUDIT_HOST_NOT, "Cisco ASA 5500");

buf = cisco_command_kb_item("Host/Cisco/Config/show_module",
                            "show module");
override = FALSE;
csc_ver = NULL;

if (check_cisco_result(buf))
{
  if (!ereg(multiline:TRUE, pattern:"CSC SSM", string:buf))
    exit(0, "CSC SSM Module not detected.");

  extract = pregmatch(multiline:TRUE, pattern:"^.*CSC SSM\s+(Up|Down)\s+([0-9\.]+).*$", string:buf);
  if (!empty_or_null(extract))
    csc_ver = extract[2];
  else
    exit(1, "Unable to obtain CSC SSM Module version.");
}
else if (cisco_needs_enable(buf))
  override = TRUE;

fix = "6.6.1164.0";

if (empty_or_null(csc_ver))
  audit(AUDIT_UNKNOWN_APP_VER, "Cisco ASA " + model);

if (csc_ver =~ "^6\.6\." &&
    ver_compare(ver:csc_ver, fix:fix, strict:FALSE) < 0 &&
    csc_ver !~ "^6\.6\.1157\.")
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : csc_ver,
    fix      : fix,
    bug_id   : "CSCue76147",
    cmds     : make_list("show module")
  );
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA " + model + ", CSC SSM", csc_ver);
