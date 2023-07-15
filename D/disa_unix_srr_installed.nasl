#TRUSTED 0bb116e094df274ebdca2a68745254f59354cc9f3a3d04231d1abdd68c17415152e71321d8e8098e971d46caf73cb954a22e43173e5d7ffdcd6f7d284ca75d9d5da466c8bf6426bfbc38078942cec0ad63e8194843f9f9849f3935aac6eabd1f0dd8f2d9717ae15987fa62a2543e223a8d51b001fb0302398da0c8676a7c780a8a2f068e6d82d41c4b2eec63a83620816fb53b2c2ceb41c3d26908f8401c35740df37057d666f0e0cbae8b5b890edeabffa1a4875e39c96bc9df6b8cf1d9ae80bbb56a09551f7082855ed539d2ff8f1c7060ccbac146e7ad6b4cbee97e3dcea66ba69f85dfd7da6ce6acb4e6020a1781f34902c79ef3c7e96cb14fd6957232ad253639ab02bf26046e758b1c34f95de946ecb8036ade7264dba93910d537fe24bcc1736f0a6b27e2bb9f7258b7c2134350c53861daf5bd89c9481b3a2a0789e6e45492f3390bf2a421f4338f72b28a383a05e560cbbf88e6d41a328ab6393afb3becab2acc2d15dbfce2bb18d134d7d4012ddc0696f90229d2d762dc3bef09d06ac3de187bf94cae70e6c2b29771259062e8133771ba1d21107686ae76e11831e602b88d86f5ad244d50f8c7225246ff44aa7b76542c21ff4279e7ad4c6479d0551a140e9ef2bee00ecc49a0c08e4031245df2deafa6c52d66cd2d07e9a7548d3f23e1b575a5b695c977c255938b32107fc002a0de4b5b6c7c64217f7e485b30
#TRUST-RSA-SHA256 41d95a60ae2da734ddbbedd84fc11ce76979a922a568579703d79a29e3a8952594992d99897b6ea68dc9262690891156701c22de207e57ecbd808a995b86049af1b59a02c0e032d0842ebdab7cf3f8b26406d95d0486412c202e142fa386d6a8279302cc795105f8a0927661f4c9afa7d4898debb186a2482393c159f21a1a8700ed5f56884d6922648645fdd26e8e44d5cafd7cca4fffd851c33757f38ccf03a6db0ad9f9e20256d788cd7c80d73c936192f0cba9267c2e777ebe3b9d6856f3d0d85b2fcee9992813598027e5619cb7560c6f83ed73736b9bc9db8fbd53f402c458e53cf502989a732272ef8540ee25dcbb57293111a246359e5cee19ddf55444f28fd68d13410417c96b88e971d2147f0b6ba55c27baf351aebf52e27112db4348267992973160a686fb7f5a25ec27f79152b4c02513d6fdc6c2595ea48c5b96cbfb966896bb6941c4303d3af499f6e75888fe0a60db3fdcb3c5c647b01acda0b4a003b0cfb6cdc8aba0670f338f770286f178cd69abd90bcb977e6f30a2a6e16b65a9389d2f4ac9bb8ca22b45fbfceb7486dd1e4713ce3d89b02eb9a52efd25fb21e01e5dd2615585a9bc63d6a33135ef1852284887fa46aa1d6347abe95a897ce20af60cebf360b80489c0447a119ccb0022ab2b50b866885bc1d69ae9d8dfdc520e34de3937b4acce09fbe5dd9f2a856a3b073a92caef84180e55944a6a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69933);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"DISA Security Readiness Review Scripts Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a security auditing script present.");
  script_set_attribute(attribute:"description", value:
"The remote host has a copy of the DISA Security Readiness Review (SRR)
Scripts present.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:disa:security_readiness_review");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("local_detection_nix.inc");

ldnix::init_plugin();

var app = "DISA Security Readiness Review Scripts";
var cpe = "x-cpe:/a:disa:security_readiness_review";

var ret, script_installs, paths, path_patterns, res, line, found_install, dir, test_file, item, install_num, version;

# We may support other protocols here
if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF, 'pread');
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

script_installs = make_array();

paths = '/home /export/home ';

# by default only search certain home directory names
# unless the "Perform thorough tests" setting is enabled
if (thorough_tests)
{
  # Also search /root if the "Perform thorough tests" setting is enabled
  paths += '/root ';
  # All home directories
  path_patterns = make_list('/home/*/Start-SRR',
                            '/export/home/*/Start-SRR',
                            '/root/Start-SRR',
                            '/root/*/Start-SRR');
}
else
{
  # Specific home directories only
  path_patterns = make_list('/home/[sS][rR][rR]/Start-SRR',
                            '/home/[sS][rR][rR]/*/Start-SRR',
                            '/export/home/[sS][rR][rR]/Start-SRR',
                            '/export/home/[sS][rR][rR]/*/Start-SRR');
}

res = find_cmd(path_patterns:path_patterns,
               start:paths,
               maxdepth: 3,
               exit_on_fail:TRUE);
res = res[1];

if (strlen(res) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'No results returned from "find" command on remote host.');
}

foreach line (split(res, keep:FALSE))
{
  if (strlen(line) == 0) continue;

  if (
    line[0] != '/' ||
    "No such file or directory" >< line ||
    'stat() error' >< line || ('/home/' >!< line && '/root' >!< line)
  ) continue;

  if(line =~ INJECTION_PATTERN)
  {
    dbg::detailed_log(
      lvl:1,
      src:SCRIPT_NAME,
      msg:'Find entry matches Start-SSR but contains command injection characters, skipping',
      msg_details:{
         "line":{"lvl":3, "value":line}
      });
    continue;
  }
  # ignore lost and found directories
  if ("lost+found" >< line) continue;

  dbg::detailed_log(
    lvl:1,
    src:SCRIPT_NAME,
    msg:'Find entry matches Start-SSR and is not defeated',
    msg_details:{
       "line":{"lvl":3, "value":line}
    });
  script_installs[line - 'Start-SRR'] = NULL;
}

if (max_index(keys(script_installs)) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "Did not find any DISA SRR scripts.");
}

found_install = FALSE;

# try to verify scripts and grab version
foreach dir (keys(script_installs))
{
  foreach test_file (make_list('sourcedVars', 'Start-SRR'))
  {
    res = ldnix::run_cmd_template_wrapper(template:'grep SRR_ProgramVersion= $1$$2$', args:[dir, test_file]);
    if (strlen(res) == 0) continue;

    # SRR_ProgramVersion="ProgramVersion=UNIX_51-29July2011"
    item = NULL;
    foreach line (split(res, keep:FALSE))
    {
      item = pregmatch(pattern:'SRR_ProgramVersion="[^=]+=([^"]+)"', string:line);
      if (!isnull(item)) break;
    }

    if (isnull(item)) continue;

    found_install = TRUE;
    script_installs[dir] = item[1];
    dbg::detailed_log(
      lvl:1,
      src:SCRIPT_NAME,
      msg:'Found valid version',
      msg_details:{
         "dir":{"lvl":3, "value":dir},
         "version":{"lvl":3, "value":item[1]}
      });
    break;
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!found_install) exit(0, 'Unable to verify that DISA SRR scripts are present.');

install_num = 0;

set_kb_item(name:'DISA_SRR/Installed', value:TRUE);

foreach dir (keys(script_installs))
{
  version = script_installs[dir];
  if (isnull(version)) continue;

  set_kb_item(name:'DISA_SRR/' + install_num + '/Path', value:dir);
  set_kb_item(name:'DISA_SRR/' + install_num + '/Version', value:version);
  register_install(
    vendor:"DISA",
    product:"Security Readiness Review",
    app_name:app,
    path:dir,
    version:version,
    cpe:cpe);

  install_num ++;
}

set_kb_item(name:'DISA_SRR/num_instances', value:install_num);
report_installs(app_name:app, port:0);
