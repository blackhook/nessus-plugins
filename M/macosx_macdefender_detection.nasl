#TRUSTED b1c10e0e2eaf4a0eb58f767472321705b5e553e9393247a7257378b8c2c55485f5c234d0a82ba718485ffdd17e2c117c73e4abdaa5cc5f5492d16b404bf474d6c191b69bb21d0934977a581c7df94027995ea9f715b7a3e14caeb3bfa44beb294bac39b504404feb8b848bb0c75a951b03659447df8e46f2e46f3e626c347977609ab6993abc0f49a603e05bfc115158e435d48c7e11495ff9a797c65d3ab5c36447a0dd812aca3d9d557c4a66419d1a5a273c8417e0edefe96da5513fd2808a147ac8834efa84f833c3ce9820f8ceacb967c889bcf20386d2666a3725a69cda6d2c476295239b9cd0875f713ff08e524e4ff9a662e3f265eba03e6356f96f2f4db19758fff598d5a16c72c577672597a63382a66cede30de3cc91636f5583a987dbdcf0f52170cf5d81e02718e3841826ff55630e8ba4c80e41cabbc587af3c9f7fd095dda91f98e52e5d1719b39cd37f7c263cfa8d68e498e5f66490a4bd47f9a0bb66897782bb9d7a369889c1d4939f7b2cda6a8ec8caedcaebad30d02d28043cafb2b7cea6c02726b41427ea58adccc3a745b41be02ac05b70983a23d39565b9228ec70f7dfd030b72367d83c757ffa720161f4e06703f72d043e94f4753ccf1ad7a5beed126e36943502ee6fee29762a0026effe0703acdfa1c6fa6c5b053993374f8a60175e1e74302bc7a11bc3fb715587f0b27fbec5b15c0689219bb
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(54832);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/05");

  script_name(english:"Mac OS X Mac Defender Malware Detection");
  script_summary(english:"Checks for evidence of MacDefender");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host appears to have been compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus has found evidence that a fake
antivirus software named Mac Defender (alternatively, MacDefender,
MacGuard, MacProtector or MacSecurity) is installed on the remote Mac
OS X host. 

The software is typically installed by means of a phishing scam
targeting Mac users by redirecting them from legitimate websites to
fake ones that tell them their computer is infected with a virus and
then offers this software as a solution. 

Once installed, the malware will perform a 'scan' that falsely
identifies applications such as 'Terminal' or even the shell command
'test' ('[') as infected and will redirect a user's browser to porn
sites in an attempt to trick people into purchasing the software in
order to 'clean up' their system."
  );
  # http://nakedsecurity.sophos.com/2011/05/02/mac-users-hit-with-fake-av-when-using-google-image-search/
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?abf43744"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4650"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Follow the steps in Apple's advisory to remove the malware."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item_or_exit("Host/MacOSX/packages");


apps = make_list(
  "MacDefender",
  "MacGuard",
  "MacSecurity",
  "MacProtector",
  "MacShield"
);

report = '';
foreach app (apps)
{
  # Look for a couple of different indicators.
  info = make_array();

  # - application directory.
  appdir = '/Applications/' + app + '.app';
  cmd1 = 'test -d \'' + appdir + '\' && ls -ld \'' + appdir + '\'';

  # - active process.
  #   nb: this just lists all processes.
  cmd2 = 'ps -axwww -o user,pid,command';

  # - login items.
  #   nb: this just lists all login items.
  cmd3 = '(echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID |awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -f "$Home"/Library/Preferences/com.apple.loginitems.plist  && /usr/bin/defaults read "$Home"/Library/Preferences/com.apple.loginitems; done';

  results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3), exit_on_fail:FALSE);
  if(!isnull(results))
  {
    if (strlen(results[cmd1]) >= strlen(app) && app >< results[cmd1])
    {
      info["Application directory"] = appdir;
    }

    if (!strlen(results[cmd2])) exit(1, "Failed to get a list of active processes.");
    else
    {
      matches = egrep(pattern:'('+app+'\\.app/|MacOS\\/'+app+')', string:results[cmd2]);
      if (matches)
      {
        info["Active process"] = join(matches, sep:"");
      }
    }

    if (strlen(results[cmd3]))
    {
      user = "";
      foreach line (split(results[cmd3], keep:FALSE))
      {
        match = pregmatch(pattern:'^/Users/([^:]+):', string:line);
        if (match) user = match[1];

        match = pregmatch(pattern:'^ +Path = "(.+/'+app+'\\.[^"]*)"', string:line);
        if (match && user) info["Login item"] += user + ' (' + match[1] + ')\n';

        if (preg(pattern:'^} *$', string:line)) user = '';
      }
    }

    if (max_index(keys(info)))
    {
      max_item_len = 0;
      foreach item (keys(info))
      {
        if (strlen(item) > max_item_len) max_item_len = strlen(item);
      }

      report += '\n  - ' + app + ' : ';
      foreach item (sort(keys(info)))
      {
        val = info[item];
        val = str_replace(find:'\n', replace:'\n'+crap(data:" ", length:max_item_len+11), string:val);
        val = chomp(val);

        report += '\n      o ' + item + crap(data:" ", length:max_item_len-strlen(item)) + ' : ' + val;
      }
      report += '\n';
    }
  }
}

if (report)
{
  report = data_protection::sanitize_user_paths(report_text:report);
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:report);
  else security_hole(0);
}
else exit(0, "MacDefender is not installed.");
