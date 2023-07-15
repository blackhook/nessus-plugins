#TRUSTED 721376cb165a3b4e7e1f5f08e16154a63a51f1816a6be598f6481dbc1c6bb18044773c2b1bdaf83154a8e38fd20e0f1563dc0a7294bbd09196069a8f50d94f73b605e044dffcf4a1aa71567b1b3bffa0220c1921bdbcf09e28b05729c9a130fe412a0483bbec055e7b115c03643d3f505d3390d713b97461bf67073f6f73aa0eb924a373b6fea7bff1c103142083fcadca05f59b43a624cdaf04c0507446e7d965e3cbbe3de77f228feb55f6885fe9ec949d7d70f49ee853fe0297d0159c66db9b9e9cb90e597f89b83344904fdeb12108be9716ecb8a3aa2df877e74b323968b4fde3d7020bbc8a623055a9fd6875c68a97c63959aabe3d8f3c8b8043e39793cb9e483621d09669066a613d888f68e19ff5acf7242499769adf28befe7d8498ecfec03c1c28ab76630031442da1ba7b46d0d555852b26d5753dced42578bc20ff405676a1e0362ed769bd0ea348a99f47d0102d9023e7fbffe4856356fa78b3d714ec2d6ffadfe67921b7cf5548265be5911c8bc1287a32755d89d8cf81251de5b0dfbc1738359e0109ca405322367cf61085eecd3b737dfe0ca33eebe25e23e25ed0363a40bfb6aff1c8d97ead058238e9fa2d1a753385f251b30fce4c7a2fa307228457461235c4079055ac39dea711675f2590c01d10890db66913f6d5010ca085ffcee78cbcd8df8c392b3c8c3d4781328227de6bb86e22e44d14a4ddc1
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32320);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2008-0166");
  script_bugtraq_id(29179);
  script_xref(name:"CERT", value:"925211");
  script_xref(name:"EDB-ID", value:"5720");

  script_name(english:"Weak Debian OpenSSH Keys in ~/.ssh/authorized_keys");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH host is set up to accept authentication with weak
Debian SSH keys.");
  script_set_attribute(attribute:"description", value:
"The remote host has one or more ~/.ssh/authorized_keys files
containing weak SSH public keys generated on a Debian or Ubuntu
system.

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL.

This problem does not only affect Debian since any user uploading a
weak SSH key into the ~/.ssh/authorized_keys file will compromise the
security of the remote system.

An attacker could try a brute-force attack against the remote host and
logon using these weak keys.");
  script_set_attribute(attribute:"solution", value:
"Remove all the offending entries from ~/.ssh/authorized_keys.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0166");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("audit.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");

uname = get_kb_item("Host/uname");
if (empty_or_null(uname))
    audit(AUDIT_KB_MISSING, "Host/uname");
else if ("Linux" >!< uname)
    audit(AUDIT_OS_NOT, "Linux");

SSH_RSA = 0;
SSH_DSS = 1;

function file_read_dword(fd)
{
  local_var dword;

  dword = file_read(fp:fd, length:4);
  dword = getdword(blob:dword, pos:0);

  return dword;
}

function find_hash_list(type, first, second)
{
  local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

  if (type == SSH_RSA)
    file = "blacklist_rsa.inc";
  else if (type == SSH_DSS)
    file = "blacklist_dss.inc";

  if ( ! file_stat(file) ) return NULL;

  fd = file_open(name:file, mode:"r");
  if (!fd) return NULL;

  main_index = file_read_dword(fd:fd);

  for (i=0; i<main_index; i++)
  {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == first)
    {
      file_seek(fp:fd, offset:offset);
      sec_index = file_read_dword(fd:fd);

      for (j=0; j<sec_index; j++)
      {
        c = file_read(fp:fd, length:1);
        offset = file_read_dword(fd:fd);
        length = file_read_dword(fd:fd);

        if (c == second)
        {
          file_seek(fp:fd, offset:offset);
          tmp_list = file_read(fp:fd, length:length);

          len = strlen(tmp_list);
          pos = 0;

          for (j=0; j<len; j+=10)
            list[pos++] = substr(tmp_list, j, j+9);
          break;
         }
      }
      break;
    }
  }

  file_close(fd);

  return list;
}

function is_vulnerable_fingerprint(type, fp)
{
  local_var list, i, len;

  list = find_hash_list(type:type, first:fp[0], second:fp[1]);
  if (isnull(list))
    return FALSE;

  len = max_index(list);

  for (i=0; i<len; i++)
    if (list[i] == fp)
      return TRUE;

  return FALSE;
}

function wrapline()
{
  local_var ret;
  local_var i, l, j;
  local_var str;
  str = _FCT_ANON_ARGS[0];
  l = strlen(str);
  for ( i = 0 ; i < l; i += 72 )
  {
    for ( j = 0 ; j < 72 ; j ++ )
    {
       ret += str[i+j];
       if ( i + j + 1 >= l ) break;
    }
    ret += '\n';
  }
  return ret;
}

function get_key()
{
  local_var pub, public, pubtab, num, i, line,blobpub,fingerprint,ret ;
  local_var file_array, keyfile, filename, home, text;
  local_var pub_array;
  local_var report;
  local_var home_report;
  local_var flag;
  local_var path;
  local_var file;

  text = _FCT_ANON_ARGS[0];
  if ( ! text ) return NULL;
  home_report = NULL;
  home = split(text, keep:FALSE);
  home = home[0];
  if(home[strlen(home)-1] == "/") home += ".ssh/";
  else home += "/.ssh/";
  file_array = split(text, sep:"## ", keep:FALSE);
  foreach keyfile (file_array)
  {
    line = 0;
    flag = 0;
    pub_array = split(keyfile, keep:FALSE);
    filename = pub_array[0];
    report = '\n'+"In file " + home + filename + ':\n';
    foreach pub ( pub_array )
    {
      if ("# NOT FOUND" >< pub || "id_dsa.pub" >< pub || "id_rsa.pub" >< pub || "authorized_keys" >< pub || "### FINISHED" >< pub)
        continue;

      line ++;
      if ( pub !~ "ssh-[rd]s[sa]" ) continue;
      public = ereg_replace(pattern:".*ssh-[rd]s[sa] ([A-Za-z0-9+/=]+) .*$", string:pub, replace:"\1");
      if ( public == pub ) continue;

      blobpub = base64decode(str:public);
      fingerprint = substr(MD5(blobpub), 6, 15);
      if ("ssh-rsa" >< blobpub)
      {
        ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
      else
      {
        ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
    }
    if( flag > 0 ) home_report += report;
  }

  if ( empty_or_null(home_report) ) return NULL;
  return home_report;
}

# Decide transport for testing
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# ignore mountpoints if thorough tests is not enabled
if (!thorough_tests)
  cmd = info_send_cmd(cmd:'cat /etc/passwd | cut -d: -f6 | grep -v "[;&|'+"\"+'`$]" | while read h; do ( ! mountpoint $h > /dev/null 2>&1;) && [ -d "$h/.ssh" ] && echo "### HOME: $h" && (for f in id_rsa.pub id_dsa.pub authorized_keys; do echo "## $f"; cat "$h/.ssh/$f" 2>/dev/null || echo "# NOT FOUND"; done); done; echo "### FINISHED"');
else
  cmd = info_send_cmd(cmd:'cat /etc/passwd | cut -d: -f6 | grep -v "[;&|'+"\"+'`$]" | while read h; do [ -d "$h/.ssh" ] && echo "### HOME: $h" && (for f in id_rsa.pub id_dsa.pub authorized_keys; do echo "## $f"; cat "$h/.ssh/$f" 2>/dev/null || echo "# NOT FOUND"; done); done; echo "### FINISHED"');

if ( ! cmd || "## id_rsa.pub" >!< cmd)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "Failed to get the contents of the /etc/passwd file.");
}
homes = make_list();

foreach home ( split(cmd, sep:"### HOME: ", keep:FALSE) )
{
  homefold = split(home, keep:FALSE);
  homefold = homefold[0];
  if(empty_or_null(homefold) || homes[homefold]) continue;
  else homes[homefold] = home;
}

foreach home ( homes )
{
  report += get_key(home);
}

if (info_t == INFO_SSH) ssh_close_connection();

if (report)
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else
  audit(AUDIT_HOST_NOT,"affected");
