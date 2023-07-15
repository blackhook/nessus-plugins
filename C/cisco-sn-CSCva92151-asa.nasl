#TRUSTED 47c4e6469aff1233f910eebc3edeb84828b6827f424e6b8c5707f1d60552aee77e8adde1ad1594b7ca853a78cb3d4d2d45437589d8a23249f60eb058a7a3fd915ce96801d115ed63970cc7909d74c1bbc06b544d75e012e39d8a30b9bbe20fdfb2b8a50f44b84e8acf3ca309eda5cd2c7a008aa3bebb360dac2c5d56365aa1c8b4a7c491ae79c3f73871ee89c405748fe5511d543d662ff40650c262fa79676045752c72a8a2df2b87335124c9feacda3130fdc74ef85b5dbac92ec50a1a2370db0a8abb3bdfedff0ca949c74f4d9d5df21edfa230916b19afaaec1f02f6d1a606ddd7f18556294977f774a24c73cefdf8a0c77069999353a837b39a513bfe82bd58fcb6d71037812719e1c00b376a95673efb65b8ae9f90ede16110c7c90503346cea4a3c120e828f2e50b2947b4a54f29d2167d99418ff0e2a4af298c75e39391be6487e0d6baa133408ad091c73c401260be810a690da14529ebf3b691e4f4157589ae56408f21ba8a761dbf99b4005df9a631a737ec4855baab2066894016e9d2c08f57adeefd592bc0ec998ad149dd44b50c06c907a54ccdc782c2b34a15a7b48ddf7e49f412eea8237a9472915e2718ebef846ab18f851458bae018c4220d09d1ac454138cfacd71f8ef6547f07d5a054bcf4a7b2821854e97c8b4fcf4208c513eb01127c147dd553637d82a12cd6529a8047c625dad94dd04f19d44c3
#TRUST-RSA-SHA256 ac0ca2e96036664940a61c9cbfd90744adf77a0f0f664b4b941031c4ec1480236dddd9cbde8aebebe4d055d082f21a81877e71f17973dda809fb4cc91ec176f14118cd3d3749067310b9a3aa43fdc4b0e4b40393941dc3f5c6f6d84a78d6f985f7d70344adc71791f4580fe96566f7ea2e19faba01639aa70bf69b34a98acf1fa1e9037cbe0823005b1d926f62116aed14e5ae1160e49f85afb4ed04abab0e8ad9b9bd591d7446605b3ca6060581260da84dc9eac4274082b95bd020ed48d675f24b49b9597661fdc50d9f30dce062da0996a1815e4b3ba53efe484e45f49eafa1ebd53d7c61d91f55e533e80b74d0730f2b0bd5b6a9f65861650e17505f264977a49b3c0aaa1f354933297e317e7e6afdc186f655514aaa2c92f3b16fb5e471e0c7de5dba368af46d97249a7081b2efce30ca24b448e90483bf48d570a535089dfdc32738968453b9727abfcc5ff924055e3b6da1080bbac68264d00d9aebe2dbfeb5736883b7d5ad8cf556bc2b63ecce1059d75792e9988a8da66d5d17d5c19a10f69ef672f49280a9b8d03eee4fee455fc8d393d7234ac13afcd96138faaf712e022b8a8d9e84146f8e018a0005e7ac87dc176634cd4ea368da9daab34ecc2cb6fc2661fbe574bbcfb403f099fced2394aeba6af2cb7ae8e326a6e2df32bb3dd3d2de08e0cb0867ee0f0d36882486fa1981a5ae63aaf997286ba0eabc9888
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93113);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-6366");
  script_bugtraq_id(92521);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva92151");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160817-asa-snmp");
  script_xref(name:"EDB-ID", value:"40258");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"Cisco ASA SNMP Packet Handling RCE (CSCva92151) (EXTRABACON)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner and configuration, the version of the remote
Cisco Adaptive Security Appliance (ASA) device is affected by a remote
code execution vulnerability, known as EXTRABACON, in the Simple
Network Management Protocol (SNMP) code due to a buffer overflow
condition. An authenticated, remote attacker can exploit this, via
specially crafted IPv4 SNMP packets, to cause a denial of service
condition or the execution of arbitrary code. Note that an attacker
must know the SNMP community string in order to exploit the
vulnerability.

EXTRABACON is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?158a2c56");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva92151");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva92151. Alternatively, as a workaround, change the SNMP community
string, and only allow trusted users to have SNMP access.

Additionally, administrators can monitor affected systems using the
'snmp-server' host command.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6366");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Convert 'Cisco versions' to dot notation
# a.b(c.d) to a.b.c.d
# a.b(c)d  to a.b.c.d
function toVerDot(ver)
{
  local_var ver_dot = str_replace(string:ver, find:'(', replace:'.');
  local_var matches = pregmatch(string:ver_dot, pattern:"^(.*)\)$");

  if (matches) ver_dot = matches[1];
  else ver_dot = str_replace(string:ver_dot, find:')', replace:'.');

  return ver_dot;
}

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

app = "Cisco ASA";

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

ver_dot = toVerDot(ver:ver);

fix = FALSE;

# versions 7.2, 8.0-8.7
if (ver =~ "^[78]\.[0-7]")
{
  # won't check granularity for this
  # affected; migrate to 9.1.7(9) or later
  fix = "9.1.7(9)";
}
# versions 9.0-9.6
else if (ver =~ "^9\.[0-6]")
{
  match = pregmatch(string:ver, pattern:"^9\.([0-9])");
  if (!isnull(match))
  {
    if (match[1] == "0")      fix = "9.0.4(40)";
    else if (match[1] == "1") fix = "9.1.7(9)";
    else if (match[1] == "2") fix = "9.2.4(14)";
    else if (match[1] == "3") fix = "9.3.3(10)";
    else if (match[1] == "4") fix = "9.4.3(8)";
    else if (match[1] == "5") fix = "9.5(3)";
    else if (match[1] == "6") fix = "9.6.1(11)";
  }
}

fix_dot = FALSE;
if (fix) fix_dot = toVerDot(ver:fix);

if ((!fix_dot) || ver_compare(ver:ver_dot, fix:fix_dot, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

override = FALSE;
snmp_disabled = FALSE;
if (get_kb_item("Host/local_checks_enabled"))
{
  # Check if SNMP is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config",
    "show running-config"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"no snmp-server enable", string:buf))
      snmp_disabled = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (snmp_disabled)
  audit(AUDIT_HOST_NOT, "affected because the SNMP server is not enabled");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
