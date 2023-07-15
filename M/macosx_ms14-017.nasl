#TRUSTED 00cdbc5712a6d8ea6cfb483e8d40a26df2fbfd378ee00561545395583b605748fb3c62fcea78daabdd344ef4a10b671ce07bb93f2b4a122022912a11222f2ec0cd90562907b8c69f25ba98021eefb859f392239cf98d402219ff7dc28bdf32b06de273dd7e4916c17b8cd7fafcda2fb5993e55381545d17e5be2562f17fd6b8ed9a2ce77b59cf4f02530a69ba2bd4f99055e32d000b2d0ab77dc63871dbaefff8dff31549e1fbc62b4ec92c96db594fc47daaa0d81eac867e4b2bc6bbbeee550cfedd045da706663d73ac02a7b9b0d5a34a200b70211d1c4c717df20a54cf7842127055dd91394390ec679ff180b960750717e09708ebd4d13168e55c04180d0a787668b60c7c4054ba6eb33fe5f0b21f1b92727bcd32db163f0dd379c180d165ca99f9fa37d27fd62e4be1d01565f798d4300ca5e33ba4b94a60d76e22b7f81b73f89bd3c4fbef717a2b393ec32d9166789f75461c4c9d59a4beb9b5101390c80227c2137f70cad63764af36639466188839c8de650fccb4b9b50ebd36252ba95ac02875520df272e84b1f1d08b440ec535272f1d39f33c68a7494af51a002474d09deb2afd4cc554332ea03fe9989151ec758c2b9d2d1acf2471f5ba80be32023d95b9b394c5e05b5123fbdfffe17e1833bb627bdb402d13a2c5ef3c0439d6cb72fc6afc9220f667202a6b4af46f6d7410e3f165274d12f46318f46131f927
#TRUST-RSA-SHA256 07a8353c66dbbe41ac17f38f434609f42c1c6ac5d5cd1fab591d6911bca1b7b587712831c4575668a612d9947531d6fdfe25e921e5d02c25cf31bab0420a3759c92ce7c6180a29cfcbba075b9663df2c86d7a5214605e39783d9298c344d7b09c82bb644523255a6f28222f8f76e11558c70912c6dd36efe1410c6d2d88145d061b0e7955bcc5001d6bd3a67db671ffa44f11dc7467008e463151f2855e9e830968115c3a083de7f1f0fdac1a579f8b3381849f16f5a20ecff9a0ff9d281889cb41af6b789cde3fa92ada0874cb71d183321547052faf09a151c7e125662568e6f822a51e8d2eacd55ce9c74f69e22a66b3ba4fe59aa990c43aec41ad2dd18cf2a9ab55b102185923b6660134480be6ecdfb63e3f806f5eefa18f1a2227ced50488dae3771b40d8ec5f52e54f981e0710543bc550a69645c34090780971ce4d3e8cc646e58be114870ff78ad3e782968527b9df1f035c7d6757200501e98455eb6ba30a002449c3872274a947fce87e11324fc7b709b1786c36c896e8296e0f69159528bcc5fcbed32c22fbd5fe2c8b629b4d684351e95aae3ffa6d6e1a554d9c3d63dd4095b645915172e0e4609fceffe903c6810f9b5a085f72835fb376912f72d7d4d5807c7874136c8d8e3cb9b469771f728a044657d071bbfe9c4d5b4fba4b5771e3c6d4afe4a744dbedc8757cc387a9c8cce4642c9015ee7744139633f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73414);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2014-1761");
  script_bugtraq_id(66385);
  script_xref(name:"MSFT", value:"MS14-017");
  script_xref(name:"IAVA", value:"2014-A-0049-S");
  script_xref(name:"MSKB", value:"2939132");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");

  script_name(english:"MS14-017: Vulnerabilities in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (2949660) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by one or more unspecified memory corruption
vulnerabilities.

By tricking a user into opening a specially crafted file, it may be
possible for a remote attacker to take complete control of the system
or execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms14-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1761");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-017 Microsoft Word RTF Object Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

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


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.4.1';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
