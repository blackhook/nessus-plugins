#TRUSTED 0bfe77f24b556106190d409aef24f2e50906250021afb259affbaa0367c434e6b5ce298ef857ff52525560cd144355465df03ed5557f61402c5077dda514ffe45fde5c522e871ae78159e4c749338f2814b1c001fd0c9332792e57ef20d3b8ec63f8496601d7073fd80e71987f13c9829921737fd0718fdcb7713a8158b07881561ec220c8fcb6e9b91fd8f5f29c6f873787287d05361517f50b4351c1c0280335ea0700dd1ff0dcd2cfc139dac3ad911ec1f4193474c429adc3aebac7c5c8cb0ad2201095384f5fe5cc518ca59afc5a17130133b9ef120f5fd961879d848a07775d4d858225199a6a70a0088d5ae783bf360e714b3cd02062b732be4435824f8939fa2c9511b56dddcc8ea99350ed058b641dd24298a6e79e08c2c1858e752be1cd1439b5dfa456cd5f3e24a95f2961c8a1c0641176abfa1ccc63d2ee8ea9c90757f36f65ae672e5b161536dc2c4af003a0293d54de2ee4daaf8925a24ac6a86d61d376a48af1c02214789f1eed1e82ceb66178d6bddaecf0b6368d51cb66d176076ed2f69c74a785f6c7e6780871f1963f96ef3974faa89dce04553935570eb8bf03be73fe7ebc23b0c34ac88114146804cc31999b6dfcb1d553c8454baf38944bba103c5a046170f4b0f93e7a4596951b45002e6e271a9c94c5a94620756a17161dce572a5f0da72c9a71071f81ab460c2cefa9cc777bae51246da52bf282
#TRUST-RSA-SHA256 5bc46397bf4a74b0ce33b34885c6b2436c8690a5b1d3ee7ca92dc3a7dbce6257cfebd5d6173507ee1ea8eed03d13d8e18f0454d972c881de6152ff1b9def188a4bbecce9c2a825bef80d36087aa2423f2c8d506ac0ad183a9a7e8b402bb85c41eac4a6743c3f0c903f1e1ba1115ae4ad35862e69abebc7bad5e9125461af9bf0418540bf443f8f9e9ce7a3689a08fbc0aa6d58313bf69e7db86c3dd5169289a62923990203bc5a531cf7d6671ea0584364a808d7dc621241a941864bc88a4a81c4e92606fd059a787133eacc98c979bfa0acbb797fcd87b719bd39fdae0c3f3e498f0952891dc93e7bc02c455cbd9e2b1fec56cd122fd9154aa627fdada7b86e9e98e22d1503ad07711574fc498a913acbf2aac7524568174b0a8fc28bc89920f0463c892323201767118a478494e9aca03b26cfd8ce1f7eac0c7ecc86bd47802960fe990762a4d312f17fd7144920baf1a9a582155b3e7620fd21c59a717e675ed1aff8ae49a1b96516905c9039665890c293bfc9c20690c263691f5c8a69f90fd269ed7d06411200c1f1c1e22fb6ea4efb2cc53b3f4990df83d71268481f3ba0f05af212303905ad956a6c9c8d5a3fabba4592800321650aab79e6203fd2d72c8da200e31ad4647f56acb3a8ddc854ab1dab01d16b70ba3561462298a2533e64ae53eae69a61b3e1b558429724cb1047b51d01e043fc05ad0966af68632d47
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77971);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"GNU Bash Local Environment Variable Handling Command Injection (Mac OS X) (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is is affected by a remote code execution
vulnerability, commonly referred to as Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Bash prior to
3.2.53(1)-release installed. It is, therefore, affected by a command
injection vulnerability via environment variable manipulation.
Depending on the configuration of the system, an attacker could
remotely execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6495");
  # https://lists.apple.com/archives/security-announce/2014/Sep/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5039c7b");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1767");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1768");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1769");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9 / 10.8 / 10.7");

ver_sh = NULL;
ver_bash = NULL;

pat = "version ([0-9.]+\([0-9]+\))(\-[a-z]+)?";

cmd = "bash --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_bash_disp = item[1];

cmd = "sh --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_sh_disp = item[1];

if (ver_sh_disp)
{
  ver_sh = ereg_replace(string:ver_sh_disp, pattern:"\(", replace:".");
  ver_sh1 = ereg_replace(string:ver_sh, pattern:"\)", replace:"");
}
else ver_sh1 = NULL;
if (ver_bash_disp)
{
  ver_bash = ereg_replace(string:ver_bash_disp, pattern:"\(", replace:".");
  ver_bash1 = ereg_replace(string:ver_bash, pattern:"\)", replace:"");
}
else ver_bash1 = NULL;

fix_disp = '3.2.53(1)';
fix = '3.2.53.1';

if (
   (!isnull(ver_sh1) && ver_compare(ver:ver_sh1, fix:fix, strict:FALSE) == -1) ||
   (!isnull(ver_bash1) && ver_compare(ver:ver_bash1, fix:fix, strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver_bash_disp  +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Bash', ver_bash_disp);
