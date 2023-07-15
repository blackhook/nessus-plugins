#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83346);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:".bash_history Files Disclosed via Web Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts what may be a publicly accessible .bash_history file.");
  script_set_attribute(attribute:"description", value:
"Nessus has detected that the remote web server hosts publicly available files 
whose contents may be indicative of a typical bash history. Such files may 
contain sensitive information that should not be disclosed to the public.");
  script_set_attribute(attribute:"solution", value:
"Make sure that such files do not contain any confidential or otherwise
sensitive information, and that the files are only accessible to those
with valid credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis by Tenable Research");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('debug.inc');
include('http.inc');


function contains_pattern (text, patterns)
{
  var p;
  foreach p (patterns)
    if (preg(string:text, pattern:p, multiline:TRUE))
      return TRUE;
  return FALSE;
}

var port = get_http_port(default:80);

var files = get_kb_list('www/'+port+'/content/extensions/bash_history');
if (!isnull(files)) 
  files = make_list(files, "/.bash_history");
else 
  files = make_list("/.bash_history");

# Clear the cookiejar in case we have credentials.
clear_cookiejar();

var max_files = 10;
var n = 0;

var extra = '';
var report = '';
var cmds = "^(ls|cd|echo|cp|mv|grep|pwd|rm|rmdir|mkdir|cat|grep|df|du|chmod|chown|wget|useradd|userdel)\s+.*$";
var blacklist = ["<html", "</html", "<title", "</title", "<script", "</script"];
var pci = get_kb_item('Settings/PCI_DSS');

var caveat = 'Note, this file is being flagged because you have set your scan to \'Paranoid\'.\n' 
             + 'The contents of the detected file has not been inspected to see if it contains any of ' 
             + 'the common Linux commands one might expect to see in a typical .bash_history file.';

var f, res, dir;

foreach f (files)
{
  res = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail:TRUE);
  
  dbg::log(src:'Normal' ,msg:'\nRequest:\n' + http_last_sent_request() +
               '\nResponse Status Code:\n' + res[0] + 
               '\nResponse Headers:\n' + res[1] + 
               '\nResponse Body:\n' + res[2] + '\n'
               '----------------------------------------------');
  
  # if paranoid and not PCI, do not verify the contents of the response body
  if (report_paranoia == 2 && !pci) 
  {
    if (!empty_or_null(res[2]) && 200 >< res[0])
    {
      report += '  - ' + f + '\n\n' + caveat + '\n';
      n++;
      if (!thorough_tests && n > max_files) 
        break;
    }
  }
  
  # if not paranoid, try and verify contents of .bash_history to see if it 
  # contains any of the most commonly used linux commands stored in cmds
  # and does not have any common HTML tags
  else
  {
    if (preg(string:res[2], pattern:cmds, multiline:TRUE))
    {
      if (contains_pattern (text:res[2], patterns:blacklist))
      {
        dbg::log(src:'Normal' ,msg:'Excluding ' + string(f) + ' because it contains a blacklisted html tag.\n');
        continue;
      }
      report += '  - ' + f + '\n';
  
      n++;
      if (!thorough_tests && n > max_files) 
        break;
    }
    else
    {
      dbg::log(src:'Normal' ,msg:'Excluding ' + string(f) + ' because it contains no bash commands.\n');
    }
  }
}

# If thorough check each of the directories
if (thorough_tests)
{
  foreach dir (cgi_dirs())
  {
    # Skip doc root since we covered up above already
    if (dir == "")
     continue;

    f = dir + "/.bash_history";
    res = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail:TRUE);
    dbg::log(src:'Thorough Tests' ,msg:'\nRequest:\n' + http_last_sent_request() +
                               '\nResponse Status Code:\n' + res[0] + 
                               '\nResponse Headers:\n' + res[1] + 
                               '\nResponse Body:\n' + res[2] + '\n'
                               '----------------------------------------------');
    
    # if paranoid and not PCI, do not verify the contents of the response body
    if (report_paranoia == 2 && !pci) 
    {
      if (!empty_or_null(res[2]) && 200 >< res[0])
        report += '  - ' + f + '\n' + caveat + '\n';
    }
    
    # if not paranoid, try and verify contents of .bash_history to see if it 
    # contains any of the most commonly used linux commands stored in cmds
    # and does not have any common HTML tags
    else
    {
      if (preg(string:res[2], pattern:cmds, multiline:TRUE))
      {
        if (contains_pattern (text:res[2], patterns:blacklist))
        {
          dbg::log(src:'Thorough Tests' ,msg:'Excluding ' + string(f) + ' because it contains a blacklisted html tag.\n');
          continue;
        }
        report += '  - ' + f + '\n';
      }
      else
      {
        dbg::log(src:'Thorough Tests' ,msg:'Excluding ' + string(f) + ' because it contains no bash commands.\n');
      }
    }
  }
}

if (report)
{
  report =
    '\nThe following .bash_history files are available on the remote server :' +
    '\n' +
    '\n' + report;
  security_report_v4(port:port, severity : SECURITY_WARNING, extra:report);
  exit(0);
}
else 
  exit(0, 'No publicly accessible .bash_history files were found on the web server listening on port '+port+'.');
