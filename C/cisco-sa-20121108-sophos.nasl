#TRUSTED 46dae5af0f1d6573f756444c0281621be1cbbdbbdd09a0cc88c508418f8cc47541714bad516550f8d38ecf65fe3d361214885557a882d392246404007b0170d7f093d7a83d3f5ccd16db0adb5af0ac87e920d85b517fa6c178a63aa1a7941b956f06d94bbad7773f5a0278077eea130f633c96c093ee29a1c2f8460ffac5b9c16140496f6b0aa9eec9f0ffbd8a1bb5cbd083b27988ecdc6d6e7d62816fd8f8eb89dae9dbb744352102c02280896528993b906497ed7f17b1a9ca31b333b425b3be5a7e9329735a9497f2d0f411cd623463cd883a7ec98a5689da93b8eada12fdcf6b24071c17906310d038787df291de45fb5714673f1e8b159d83488a9dae0936c0c1a4b9b7a62c7bc90d50ed19284301942bba2c57def825ba48fea2110166ce281a84b58f759ba1eb24d4a883027ab0dc8a3110a91fc5e67231a8af2ece8452f6f3db1bb3150b2e8d3f6acbb9b60f8f55a75b2e8dd2f8be91029e1740d20ba097b94da254a41a9040c301f73924a93ca09558e7f66e3daecd7a5065f135ebb8d991a7ae28f8952aa80c9da2178db974dbbea1d46bbdce2830d5198f1d098e56d55f26d6cf5864d5a4441c052e92ce5d6170e8f002959953f2a13e6843e6e19e91363fe64d43547cdb35deb99cb5763733518efe1cf036becfc39c52b873e6ba2eb529c0d7626551aa1785748bd8b6583921a541023ca524b6c47032e2bb50
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70125);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_bugtraq_id(56401);
  script_xref(name:"CERT", value:"662243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121108-sophos");
  script_xref(name:"IAVA", value:"2012-A-0203-S");

  script_name(english:"Cisco IronPort Appliances Sophos Anti-Virus Vulnerabilities (cisco-sa-20121108-sophos)");
  script_summary(english:"Checks the Sophos Engine Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device uses an antivirus program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IronPort appliance has a version of the Sophos
Anti-Virus engine that is 3.2.07.352_4.80 or earlier. It is,
therefore, reportedly affected by the following vulnerabilities :

  - An integer overflow exists when parsing Visual Basic 6
    controls.

  - A memory corruption issue exists in the Microsoft CAB
    parsers.

  - A memory corruption issue exists in the RAR virtual
    machine standard filters.

  - A privilege escalation vulnerability exists in the
    network update service.

  - A stack-based buffer overflow issue exists in the PDF
    file decrypter.

An unauthenticated, remote attacker could leverage these issues to
gain control of the system, escalate privileges, or cause a denial-of-
service.");
  script_set_attribute(attribute:"see_also", value:"https://lock.cmpxchg8b.com/sophailv2.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/en-us/support/knowledgebase/118424.aspx");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121108-sophos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16e77af");
  script_set_attribute(attribute:"solution", value:
"Update to Sophos engine version 3.2.07.363_4.83 as discussed in Cisco
Security Advisory cisco-sa-20121108-sophos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/AsyncOS/Cisco Email Security Appliance", "Host/AsyncOS/Cisco Web Security Appliance");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version_cmd = get_kb_item("Host/AsyncOS/version_cmd");
if (isnull(version_cmd)) audit(AUDIT_OS_NOT, "Cisco AsyncOS");


version = NULL;
if (get_kb_item("Host/AsyncOS/Cisco Email Security Appliance"))
{
  sock_g = ssh_open_connection();
  if (!sock_g) exit(1, "Failed to open an SSH connection.");

  cmd = "antivirusstatus sophos";
  output = ssh_cmd(cmd:cmd+'\r\n', nosudo:TRUE, nosh:TRUE);

  ssh_close_connection();

  if ("SAV Engine Version" >< output)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:output);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else if ("Unknown command or missing feature key" >< output)
  {
    exit(0, "The remote Cisco Email Security Appliance does not include a version of Sophos Anti-Virus.");
  }
  else
  {
    exit(1, "Unexpected output from running the command '"+cmd+"'.");
  }
}
else if (get_kb_item("Host/AsyncOS/Cisco Web Security Appliance"))
{
  if ("SAV Engine Version" >< version_cmd)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:version_cmd);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else exit(0, "The remote Cisco Web Security Appliance does not include a version of Sophos Anti-Virus.");
}
else exit(0, "The host is not a Cisco IronPort ESA or WSA.");


# nb: Cisco's advisory says 3.2.07.352_4.80 and earlier are affected
#     but tells customers that version 3.2.07.363_4.83 fixes the issues.
recommended_version = NULL;
if (version =~ "^[0-9][0-9.]+_[0-9][0-9.]+$")
{
  version_num = str_replace(find:"_", replace:".", string:version);
  if (ver_compare(ver:version_num, fix:"3.2.07.352.4.80", strict:FALSE) <= 0) recommended_version = "3.2.07.363_4.83";
}
else if (version =~ "^[0-9][0-9.]+$")
{
  if (ver_compare(ver:version, fix:"4.80", strict:FALSE) <= 0) recommended_version = "4.83";
}
# These next two cases shouldn't happen.
else if (isnull(version)) exit(1, "Failed to identify if the remote Cisco IronPort appliance uses Sophos Anti-Virus.");
else exit(1, "Unrecognized format for the Sophos Anti-Virus engine version ("+version+") on the remote Cisco IronPort appliance.");


if (isnull(recommended_version)) audit(AUDIT_INST_VER_NOT_VULN, 'Sophos engine', version);

if (report_verbosity > 0)
{
  report =
    '\n  Sophos engine installed version   : '+ version +
    '\n  Sophos engine recommended version : '+ recommended_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
