#TRUSTED 939f39ce9b400f461aad88b17704abad25da359e565ab4188a80bee1f54bc652a9ae8d8505f8142ac837939b906d7aebe4e946758380b2d723c505dc38da82432081a0df7d2aba65eeb2cde64cdd337321219833649aab4e2f6a975c2cc5abb7b6288a717099bcaaea67c8206d56d44755662e9f10d6729f271d09815497d5bb1da5bc7ab0ca2edbddee713163aa122834b98a85f19f5245d47c7c6d345282ca19f45cbb5067764b28caec2616693ce939d8dc1586a205327cbe31035939fdfbff59fb83bc83957e63cb231a9e32c3772b778293165792ba5743cfc0389fc256c8673f0dfa77169e8bb611bdcc700150c148e8e8ffaff493157a7f1bdc8ed71d965a11dc0f59eebc9da314ebf3b8379896562194364f8ff51bd347f5123c61241e15f8d16e06dc9e0c2f1def36318398634c1e0073d2ec692df18f6863c9dadb6995a64d82c792c43ab03213ba1a8fbe67e426b1729112bfa5bd897cc00965647f9dc068b79675e99857c9d844163c21160780b7a3a4f4b64b2723383c29eaaa7e0295d90cbfbdd55f36a8009873e96dd45a09d6aac439fd1b761740c12c486be82da6900cc93dcf671603a656d93c0f000492a6509be33aeb43e01f07300df4d3d8965d78e57816449a7f83c6d894b0067772d61e38cb1d27edf2a17eba6bfd9a3621584eed19e5cbe1376f00963eafe6d67364fa26d78f4f52453f76516fa4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69378);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug34485");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco IOS XE (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link
State Advertisement (LSA) database. A remote, unauthenticated attacker
can exploit this vulnerability, via specially crafted OSPF packets, to
manipulate or disrupt the flow of network traffic through the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a643e96");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

#
# @param fix     The second version string.
# @param ver     The first version string.
# @param strip   A character/string which should be removed
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function ver_cmp(fix, ver, strip)
{
  local_var ffield, vfield, flen, vlen, len, i;

  # strip out any desired characters before the comparison
  if (strip)
  {
    ver = str_replace(string:ver, find:strip, replace:'');
    fix = str_replace(string:fix, find:strip, replace:'');
  }
  # replace ( and ) with dots to make comparisons more accurate
  ver = ereg_replace(pattern:'[()]', replace:".", string:ver);
  fix = ereg_replace(pattern:'[()]', replace:".", string:fix);
  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);

  vlen = max_index(ver);
  flen = max_index(fix);
  len = vlen;
  if (flen > len) len = flen;
  # Compare each pair of fields in the version strings.
  for (i = 0; i < len; i++)
  {
    if (i >= vlen) vfield = 0;
    else vfield = ver[i];
    if (i >= flen) ffield = 0;
    else ffield = fix[i];

    if ( (vfield =~ "^\d+$") && (ffield =~ "^\d+$") )
    {
      vfield = int(ver[i]);
      ffield = int(fix[i]);
    }
    if (vfield < ffield) return -1;
    if (vfield > ffield) return 1;
  }
  return 0;
}

flag = 0;
override = 0;
report_extras = "";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (version =~ "^2(\.[0-9]+)?") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?SG$") {fixed_ver = "3.2.7SG" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?SE$")
{
  if (ver_cmp(ver:version, fix:"3.2.2SE", strip:"SE") < 0)
  {
    fixed_ver = "3.2.2SE";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.2.7SG", strip:"SG") < 0)
  {
    fixed_ver = "3.2.7SG";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SQ$") {fixed_ver = "3.3.0SQ" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?XO$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?SG$") {fixed_ver = "3.4.1SG" ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.4.1SG", strip:"SG") < 0)
  {
    fixed_ver = "3.4.1SG";
    flag++;
  }
}
else if (version =~ "^3\.5(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.6(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.7(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.8(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.8.2S", strip:"S") < 0)
  {
    fixed_ver = "3.8.2S";
    flag++;
  }
}
else if (version =~ "^3\.9(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.9.1S", strip:"S") < 0)
  {
    fixed_ver = "3.9.1S";
    flag++;
  }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
