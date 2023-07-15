#TRUSTED 64ef950a5bf35499bac7ec60fefe4211847ca07e0a3c5beb94180f07fb72ef94577286740f5577a6d957414820d924bc7ec27b04277673f85cfe08875d395a6cc8c0284109fea583e6fde4051ae395e20a95bcac11ceb5c958b9b496d16f8a2ef86c9200d09693aa91492a93483a60701c04330f72b2297bef25c49506f65408e64cccd75cc899ec41df363d1d8f507caffa11afde3e7fb7d6ae6e888e50a88dbd9035e3fdb1517665b3278656d01d8e4aec16ca239715052f91b50f9875ccf97d26f9a15ea86e7cc9294379d1e23672047a03d0cbd420d34bd2c98493f5c36680d9292f7d139a2f3c1db24368ef5ec65899c0e5fe3c1adaf2445b0c7a3eea9afc8a032b88191bbfbbdee739ab542a8ff25bd3aaac4247809d39b11c641538a44d5cbe5888614c8c08b80d4d3c5f6025b971e4e28fb55336f8f442e565d30ffde3c7d0ab4d3a5d84078f6d5fcb403f9ce4d119025e027b64d45a879a59217ac2cf394de4fa74c8f085086fe9630678aa47f1e49169cb342657f94f73993f7df85142c81279f90c8c486c6ecc52bf9a4a7fae83d102b28c304687bd34799a9b69ba31a10517d216ec8c3f5969b12f51d21b72c0e4f7f97c75aa208c840c2e6a7a468895337183aa71a43da5ad70abd8d1e840fd4fe6df21dec85374792606714fdb0658147d98cd0369e2543721e4cc6af378c0beb79bbf781f5bfb193fe19685
#TRUST-RSA-SHA256 aca81a5d4e7c57839b95fe88aa9e3f1a7bb858af5e8bc584f5d40fe2c59133d2971443f8230ab1e2e368dc7462ee00b61ea5969c28185a3c87d2105840ad0af49aa0d292fe8561f940f89604e5b87380234f933067b8709ff99ab53705c03d53dafae8bc24ae934aaf097628cb22c3e945680447379e3e92cb81137f6df7ed6ed92788433e998ca8bd0d285c6e5d1375027610c79e051e29d07facb6aee141f9ff422ddc5570b838c6f1122d1e2978a4ecfda45039464e6e560a06783862f5bb87c8e2346588e9e828ab44a1d8878474769eff36d2c0116eb1c43de4773fa91661f1a1d71c59b866e23e93106b092b36e1a3cd1d800b835bf1be9199cc81db5e050900d6743c4aa2affc0416e182127b1cd9cb2a0ec9b4906c5f8204235fc0377f7ca0142579ac6f9a7d983f0642bdbd208e4d98d4e4aa8e5227cc938a007491e19500e3664802133504d98922f76d04d035116d089b9e474ab5d7feae59a695c6333416f4e498578816df36e7f2e5e663118f7eac4456a576c2a3473fde4ec23b35366fa6f293ad40143badb3d53eec0a5e42d58d38e1fcb8227a70d9ee9c58df8e4c26c9f4e06c119b1dcde32277123e766804a266188f5cf0b2a40da59e1836cfd7dac303e1ad85a9f2244a954242d5d207636dc7323f70cec5245dc2de12105f90fab2cfa2ecf72be78790fb58ad1e8019f7f9a042012083d511b698a674
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39435);
  script_version("1.20");
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
    "CVE-2008-5347",
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
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1106",
    "CVE-2009-1107",
    "CVE-2009-1719"
  );
  script_bugtraq_id(32620, 32892, 32608, 34240, 35381);
  script_xref(name:"Secunia", value:"35118");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 4");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.5 host is running a version of Java for
Mac OS X that is missing Update 4.

The remote version of this software contains several security
vulnerabilities.  A remote attacker could exploit these issues to
bypass security restrictions, disclose sensitive information, cause a
denial of service, or escalate privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 4 (JavaVM Framework 12.3.0)
or later."
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/17");

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
  local_var buf, ret;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(1, "Failed to get version info from '"+plist+"'.");

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 12.3.0
  if (
    ver[0] < 12 ||
    (ver[0] == 12 && ver[1] < 3)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.3.0\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
  else exit(0, "The remote host is not affected since JavaVM Framework " + version + " is installed.");
}

