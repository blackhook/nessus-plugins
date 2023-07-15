#TRUSTED 69bf0d6bab56c5c0c89b2e4d311a218d07291c8e6fbc080292e32e005d17647752b7523a195efd7926f0c4bfe3d6e1a39cbf18a5c4728b730a9c51ac8374f670131212fcf173b120cd41905a0bf1942fc92455d7bb7c4494fca560f1b49935f6dd1aeeb9de9b85adfd14427d444db4b990759e4ab908bd5080f994dfdef03ee546a54b5417f4007b1b782f0646a13939589371d06369dffcc429e150a4451bd7686cb9dfab42e84b99a8cc82cdbbc27dd8d93680cebc782d4d005868f486c20a063e3aa9932b0ecacdc2aa476a52aff00047c7b42bc7d85bb86d34ae1673490a862164e62ac437f5099abe7e96b8024d30b1d01e49ba1d31fbe31be1e8608379e99b97dde1107d4e798c48e6a6eb281c97d7caa4bd5d71b42af3ee283b229ec9efbbf24e10b7833f95fc230f7e3ace31b8ed4f36a43aaed0f5ede9ca6a19cde95b4e08bf4265c47c8356102887eafbc0ee21d6597b907ee204a4cc4cb819512caff51ba5f3a7f53fc66fa538206650bffb48999dfa73d25ead797202d086b13e43d94dc2be69124c8bd049a70b8e4179ca0202814f526d21e4175b03b5e9fa5f8fd75721393248063435987275cdce9c5ccfca4229ec4a782c979d8f4a889dd5bb697cb2f537c0b68d4a1fe3c36e91f364321ff040a6a488aaf33529698fbd1cdd64660c7161b7695392023a0c82027df7f7706870435cdbec71b4a440fe3a6a
#TRUST-RSA-SHA256 89b2ac5961d839ef4dc29acbe09556ba0ae63d601cd8dd7d29b7c5cf14da233c8eb69ece2a14e9c84236e67a1cda54f192fd1ad0fdd32920a95fca8ab36bfdc91a8630ee46345c340fbf8014ebe448ed981a96926ef4ce81734593aa1ac4a4f7e2270531f6886b03f2da7931924ecdc5a9cb36a0b4fef9aca6fb6725729a5c2ea7b2e61b31e7028ef8b7ff1d71fc1f7cd3210bf79f9cf613215e08881649b7568ddaf46a5043f7a155545978d0e41e96e31b3ec6c2a97cade74d1abc630e4ec569809bb620866ce542ae45c0b9fcc4daeee0ad59d932472a3fc9ca5becea10883c4975c06cc4e762336048ad53e281861ce6e5bdd319818d8b06b878d3bb3bbacf58e3fe5a15e12791ae7d2618f44ef469f6499a779bc459447e5130b6ee123d5d6569c5794abbd9da0a324c4406503a3ebb67a6e903533d0824b67a3660e366477f8575a17e9eb58476e45c5ab11a2af6c98affee4d8bc82e77e41a32d9551aff6d81845d754bc08beb5dd0be93e9166692617613b605b834cc7b37cac10437f63f57d41076f913bb3395bb350de3e4cd3cb89221cc2009ba3676bbe4586141058cb2701691d4733f4506f783102aae9c8d06d9f68b81f901def0145dfc5ad7607beaa90a5baaf9b1560ef7a65a55bc382ca7f78f3fe084cc0ffe111fc94f01a227cd21ecd33aeb33811813a73ba83033bab9b1457269f4205d8632d02c8771
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82768);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2015-1639");
  script_bugtraq_id(73991);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090-S");
  script_xref(name:"MSKB", value:"3055707");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Outlook
for Mac for Office 365 installed that is affected by a cross-site
scripting vulnerability due to improper sanitization of HTML strings.
A remote attacker can exploit this issue by convincing a user to open
a file or visit a website containing specially crafted content,
resulting in execution of arbitrary code in the context of the current
user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Outlook for Mac for Office 365.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

prod = 'Outlook for Mac for Office 365';
plist = '/Applications/Microsoft Outlook.app/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^15\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '15.9';
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
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, prod);
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
