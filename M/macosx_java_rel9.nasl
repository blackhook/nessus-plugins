#TRUSTED 7b6593f8ba36f08f5d1f33f70b8bb005cd5a73457dd82e13ab64be14a5922b77331f9fb941aeaa1c256726bc23c0de226513384b6b6ba5ef1949684d7678ff702359c136faea3838f70bbea15eb9f670a29b6a71992d62505313b6f0959f0db42e4bb9640716ce0b80ce130eb99f3508d83e1118648613aea50ad918dfd7a0f419893916dd186f9c3e8a65a2c19373880cf4c1baca9a73a7aae3b7a021ab1fda24b186e3a2f4811db1eb8a139ade87f89810d14b009d9ad86480b87705de22533425e0821172ac5a7ab5d98267af18f85da8c3f53be3b29d8257b1025dc6718a65b6434e4c95d693f865c56cb8c2e4d788ee3ec16456faa64c1c55c345835eb552ee317bde6b69d49857a097cb5ffee129281276883436b8edb2f7c96994445e5350d78dc91668dc611834d5479c9ce571d6d265284bf9c544508857753a8d8bb8ae7385125eb2391c1b0dde8f2024d4af35c393ba78594ffd162022ed258e7dbb4d6102f5843b9c8d98f7d74a29b6d6f9172a11bdf05b2c8814d5e50160dd44002996b0a931e7c9c6243362a5d4b5c955b85ab564ae88d0f476643178e08ae21110405ae75b994d3610cea52eb42aa604eeab50b72ae488b05a3e999607a5dce5dcddb0f875e5fdf94836f512a70c345b5a2af12e3cbb1e83af13bbd4112aca161e4b5e9734fe9203dd958546f61c9dc831cc962a0b0b0d8b4b84d2f0f90949
#TRUST-RSA-SHA256 41a8dc0e10f65d079606507ce43d7b1f87d9a2f6e66264c577bfef72c6f00ffdd2f14a9ce3de290a57a23a81bb8dd1d30a2e400affa19225f90c83be7d1d859e94a6179a422a5be90e71310c715337aec816e507bafc76788f9342cfbe0b00b114c7847d45935743f55c7202c3afd11ca27c4ea73ccc46de9fac717409b872a03793b63ff76a47e51ec6d842e9788fc8d373eb4da9adbe81e16665e675dd271144e77f18dbd5610af58a815ba07bf75d499375c56dff20564d5353cccff6068c615f9bd0c7ad1871d579ca212ab207a25c05ab2c9dc7e34e72d165ae3e2c318d63fff690ca013556a3e14d7b23f4d407ef5330d68003ea3a7ec82793c576e9ce74af147270fc1aaf864dc4550c297096544128dac92d3f241db74d5cdd0892eb81fe81f43221d7bef84c0045766d1b4816bef272d438f5512f1accde1586e95b6afa9a5f32b38367038e12d532a6701f9fc2eccf283f97dd704237894992f4449d07c7ed8aa3cfb0e7b89cb7ad830e1de7665023dead0e7347685bd623757fa0cde9f22a47d314643c5493065550bb34c851af094ec1b9d86408dca5beaba2c57b2244400c6221656a1f5d8d1c435aa2075f3ac2524c564ac39d80dc5b3c3547de8576a7f8a6ab6953e996ee16d68231fe60ba8149129e582f7af80edbd7453bb7c5bd5a7b8b1bf477dc78a3de20e165eaca38201b556d6f711a51fb34b616ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39766);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1107"
  );
  script_bugtraq_id(32892, 34240);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 9");
  script_summary(english:"Check for Java Release 9 on Mac OS X 10.4");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X older than release 9.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun/msg00004.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.4 release 9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1096");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.9.0.
  if (
    ver[0] < 11 ||
    (ver[0] == 11 && ver[1] < 9)
  ) security_hole(0);
}
