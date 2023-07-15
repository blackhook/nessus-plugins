#TRUSTED 913876aa723f886be3648f6010d3881f4059eb306f3cd8148a53b3024160ef850e908e0588c06e8047ee88e02374441926d6dc72aa4719ec6b26549de2a4a1f13910ec07c796126c919e97d6483ff5d898b61b535fe8fd365160ef201a9a057a142eb31adf95700f678a810d3539588fd60612e1ed85ca28df77d2f681da9eb3ba443ee41ddb38f555d2d3f6431691d82b5582fedf19509e6a623f1ea907646e23a89ace3d3cf25acdb18d18609fa4a375b0ad53b0d3fa798d93082b531af913e1cb3829042410feacd6d4f4fda9655c0c08ee5c55d301fd69cda8ae404bc46efebf7ebaa66ef0c322dde25b4984612c9100b12752f7d43f4662ee95ee24dba6c3673738e220d6f5b8160e563a4a05d65439f935a0486a20616e95441f13a37aff059e6ca5e236a06bc765437f5cc776d1abb766ad0768acc3d8f24150dbf299b87b12d3a64a5963b2a227823c909cf5bc6cc3cf5a43bbd31782e251bb15bc1897fe95ce20d647eb3753c38e4e41da85261f9eceae7099ddba3bb508bc3bde633e3c485749aa34d7713bfa0f5148872da8e7dbc2a7191149fb5fe1b5e4680740608f607f928cf7a462d1b14d57f6f485196dff5d524b8dfe7a8f068bed81a72e764220b6a63f304817c764a523664dc173fb69c6432eb370c8c5399c21f59449240004150a5b58a956575dec53558c9b28151969c8644da5eced81ced87e97bb
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(19782);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_name(english:"FTP Writable Directories");
  script_summary(english:"Checks for FTP directories which are world-writable.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server contains world-writable directories.");
  script_set_attribute( attribute:"description", value:
"By crawling through the remote FTP server, Nessus discovered several
directories were marked as being world-writable.

This could have several negative impacts :
  - Temporary file uploads are sometimes immediately available to
    all anonymous users, allowing the FTP server to be used as
    a 'drop' point. This may facilitate trading copyrighted,
    pornographic, or questionable material.

  - A user may be able to upload large files that consume disk
    space, resulting in a denial of service condition.

  - A user can upload a malicious program. If an administrator
    routinely checks the 'incoming' directory, they may load a
    document or run a program that exploits a vulnerability
    in client software.");
  script_set_attribute(attribute:"solution",  value:
"Configure the remote FTP directories so that they are not world-
writable.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on manual analysis");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/08");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include('audit.inc');
include('ftp_func.inc');
include('misc_func.inc');
include('global_settings.inc');
include('string.inc');
include('spad_log_func.inc');
include('lists.inc');

##
# Get FTP LIST command output via PASV mode of FTP
#
# @param [path:string] current FTP path to look for directories
# @param [commands_socket:socket] socket for FTP comands
#
# @return string output containing directories listing
##
function get_ftp_list_output(path, commands_socket)
{
  var res_code, data_port, data_socket, ls_command;
  var res_data = '';

  if (empty_or_null(path))
    ls_command = 'LIST /';
  else
    ls_command = sprintf('LIST %s', path);

  debug_log(message:'LIST command to execute: ' + ls_command);

  # Switch FTP server to PASV mode
  data_port = ftp_pasv(socket:commands_socket);

  debug_log(message:'PASV FTP Port: ' + data_port);

  # Cann't get PASV port from FTP server
  if (data_port == 0)
    audit(AUDIT_SVC_ERR, commands_port);

  data_socket = open_sock_tcp(data_port);

  if (empty_or_null(data_socket))
    audit(AUDIT_SOCK_FAIL, data_port);

  # Run LIST command to start folder's investigation
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:ls_command
             );

  debug_log(message:'FTP Command result code: ' + res_code);

  # FTP transfer confirmation code:
  # 150 Here comes the directory listing.
  # 125 Data connection already open; transfer starting.
  if (empty_or_null(res_code) || (('125' >!< res_code) && ('150' >!< res_code)))
    return res_data;

  res_data = ftp_recv_listing(socket:data_socket);

  debug_log(message:'FTP LIST command output:\n' + res_data);

  # Get transfer complete confirmation from commands FTP socket
  # 226 Transfer complete
  res_code = ftp_recv_line(socket:commands_socket);

  debug_log(message:'FTP Transaction code: ' + res_code);

  if (empty_or_null(res_code) || ('226' >!< res_code))
    audit(AUDIT_SVC_ERR, commands_port);

  # Data transfer completed. Close Data socket
  close(data_socket);

  return res_data;
}

##
# Parse FTP LIST command output and get 
#
# @param [line:string] a line from FTP LIST command output
#
# @return string with directory name / '' if the wrong input 
##
function get_dir_name(line)
{
  var result = '';

  # FTP Windows (MS-DOS style)
  # 02-19-19  05:50AM       <DIR>          1
  if ('<DIR>' >< line)
  {
    debug_log(message:'Line to parse: ' + line);
    result = pregmatch(pattern:"<DIR>\s+(.+)$", string:line);

    if (!empty_or_null(result))
    {
      debug_log(message:'Folder name: ' + result[1]);
      return result[1];
    }
  }
  # FTP Unix
  # drwxrwxrwx   1 owner    group            0 Feb 19 05:50 1
  if (line[0] == 'd')
  {
    debug_log(message:'Line to parse: ' + line);
    result = pregmatch(
               pattern:"(.+?\:\d{2}\s)(.+)",
               string:line
             );

    if (!empty_or_null(result))
    {
      debug_log(message:'Folder name: ' + result[2]);
      return result[2];
    }
  }

  debug_log(message:'Folder name: ' + result);
  return result;
}

##
# Provides the list of all directories on the target FTP server
#
# @param [path:string] current FTP path to look for directories
# @param [commands_socket:socket] socket for FTP commands
# @param [depth_limit:int] limits the depth of search for folders
#
# @return list of paths to folders
##
function dir_crawler(path, commands_socket, depth_limit)
{
  var res_data, line, dir_name;
  var directories = make_list();

  if (write_test(path:path, commands_socket:commands_socket))
    directories = make_list(directories, path);

  # Stop directory search if we've reached a limit
  if (depth_limit == 0)
    return directories;

  res_data = get_ftp_list_output(path:path, commands_socket:commands_socket);

  if (empty_or_null(res_data))
    return directories;

  # Split the FTP LIST command output and work with each directory separately
  foreach line (split(res_data, sep:'\r\n', keep:FALSE))
    if (('<DIR>' >< line) || (line[0] == 'd'))
    {
      dir_name = get_dir_name(line:line);

      if (!empty_or_null(dir_name))
        # Use a recursion to browse through the whole tree
        directories = make_list(directories, dir_crawler(
                 path:path + dir_name + '/',
                 commands_socket:commands_socket,
                 depth_limit:depth_limit-1
               ));
    }

  return directories;
}

##
# Run all the possible tests to detect if the path is writable
#
# @param [path:string] current FTP path to look for directories
# @param [commands_socket:socket] socket for FTP commands
#
# @return boolean true if path is writeable
##
function write_test(path, commands_socket)
{
  # We need a couple of tests as FTP configuation allows to configure
  # directories and files premissions separately

  # Test 1. An attempt to write a file
  if (file_write_test(path:path, commands_socket:commands_socket))
  {
    debug_log(message:'Writeable as file can be uploaded: ' + path);
    return true;
  }

  # Test 2. An attempt to create a directory
  if (directory_write_test(path:path, commands_socket:commands_socket))
  {
    debug_log(message:'Writeable as directory can be created: ' + path);
    return true;
  }

  return false;
}

##
# Attempt to create a file
#
# @param [path:string] current FTP path to look for directories
# @param [commands_socket:socket] socket for FTP commands
#
# @return boolean true if directory is writeable
##
function file_write_test(path, commands_socket)
{
  var file_name = rand_str(length:8) + '.nes';
  var file_body = 'Nessus TEST\r\n\r\n';
  var file_check = sprintf('SIZE %s', file_name);
  var file_create, file_remove, res_code, data_port, data_socket;
  var cwd = sprintf('CWD %s', path);
  var res_data = '';
  var result = false;

  debug_log(message:'FTP CWD Command: ' + cwd);
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:cwd
             );

  debug_log(message:'FTP CWD Command result code: ' + res_code);

  # Check the FTP CWD command results
  # 250: CWD command successful.
  if ('250' >!< res_code)
    return result;

  # Check the unlucky event of file already exists
  while (true)
  {
    debug_log(message:'File existence check command: ' + file_check);
    # Run SIZE command
    res_code = ftp_send_cmd(
                 socket:commands_socket,
                 cmd:file_check
               );

    debug_log(message:'File existence check result: ' + res_code);
    # File doesn't exist
    # 550: The system cannot find the file specified.
    if (empty_or_null(res_code))
      return false;
    else if ('550' >!< res_code)
    {
      file_name = rand_str(length:8) + '.nes';
      file_check = sprintf('SIZE %s', file_name);
    }
    else
      break;
  }

  file_create = sprintf('STOR %s', file_name);
  file_remove = sprintf('DELE %s', file_name);

  # Swith to ASCII transfer mode
  debug_log(message:'FTP TYPE Command: TYPE I');
  # Run STOR command to start folder's investigation
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:'TYPE I'
             );

  debug_log(message:'FTP TYPE Command result code: ' + res_code);

  # Check the FTP TYPE command results
  # 200: Type set to I.
  if ('200' >!< res_code)
    return result;

  # Switch FTP server to PASV mode
  data_port = ftp_pasv(socket:commands_socket);

  debug_log(message:'PASV FTP Port: ' + data_port);

  # Cann't get PASV port from FTP server
  if (data_port == 0)
    audit(AUDIT_SVC_ERR, commands_port);

  data_socket = open_sock_tcp(data_port);

  if (empty_or_null(data_socket))
    audit(AUDIT_SOCK_FAIL, data_port);

  # Run STOR command to start folder's investigation
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:file_create
             );

  debug_log(message:'FTP STOR Command result code: ' + res_code);

  # FTP transfer confirmation code:
  # 125 Data connection already open; transfer starting.
  # 150 Ok to send data.
  if (!empty_or_null(res_code) && (('125' >< res_code) || ('150' >< res_code)))
  {
    # Upload our test file
    send(socket:data_socket, data:file_body);
    shutdown(socket:data_socket, how:2);

    # Get transfer complete confirmation from commands FTP socket
    # 226 Transfer complete
    res_code = ftp_recv_line(socket:commands_socket);

    debug_log(message:'FTP Transaction code: ' + res_code);

    debug_log(message:'File existence check command: ' + file_check);
    # Run SIZE command
    res_code = ftp_send_cmd(
                 socket:commands_socket,
                 cmd:file_check
               );

    debug_log(message:'File existence check result: ' + res_code);
    # File does exist
    # 213: <SIZE>
    if ('213' >< res_code)
      result = true;

    # Cleaning procedures
    # 1) Delete file anyway
    debug_log(message:'File DELE command: ' + file_remove);
    # Run SIZE command
    res_code = ftp_send_cmd(
                 socket:commands_socket,
                 cmd:file_remove
               );

    debug_log(message:'File DELE result: ' + res_code);

    # 2) FTP CWD back to /
    debug_log(message:'FTP CWD Command: CWD /');
    res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:'CWD /'
             );

    debug_log(message:'FTP CWD Command result code: ' + res_code);

    return result;
  }

  close(data_socket);
  return result;
}

##
# Attempt to create a directory
#
# @param [path:string] current FTP path to look for directories
# @param [commands_socket:socket] socket for FTP commands
#
# @return boolean true if directory is writeable
##
function directory_write_test(path, commands_socket)
{
  var folder_name = 'Nessus' + rand_str(length:10);
  var dir_check = sprintf('CWD %s%s', path, folder_name);
  var dir_create, dir_remove;
  var result = false;
  var res_code;

  # Check the unlucky event of folder with the same name exists
  while (true)
  {
    debug_log(message:'Dir existence check command: ' + dir_check);
    # Run CWD command
    res_code = ftp_send_cmd(
                 socket:commands_socket,
                 cmd:dir_check
               );

    debug_log(message:'Dir existence check result: ' + res_code);
    # Folder doesn't exist
    # 550: The system cannot find the file specified.
    if (empty_or_null(res_code))
      return false;
    else if ('550' >!< res_code)
    {
      folder_name = 'Nessus' + rand_str(length:10);
      dir_check = sprintf('CWD %s%s', path, folder_name);
    }
    else
      break;
  }

  dir_create = sprintf('MKD %s%s', path, folder_name);
  dir_remove = sprintf('RMD %s%s', path, folder_name);

  debug_log(message:'Dir creation command: ' + dir_create);
  # Run MKD command
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:dir_create
             );

  debug_log(message:'Dir creation result: ' + res_code);

  # FTP response should be:
  # 257 - "DIR NAME" directory created.
  if (!empty_or_null(res_code) && '257' >< res_code)
    result = true;

  # Cleaning:
  debug_log(message:'FTP Dir remove command: ' + dir_remove);

  # 1) Run RMD command
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:dir_remove
             );

  debug_log(message:'Dir removal result: ' + dir_remove);

  # 2) Run CWD command
  debug_log(message:'FTP CWD Command: CWD /');
  res_code = ftp_send_cmd(
               socket:commands_socket,
               cmd:'CWD /'
             );

  debug_log(message:'FTP CWD Command result code: ' + res_code);

  return result;
}

##
# Put information to debug log if it's enabled 
#
# @param [message:string] string to put in debug log
##
function debug_log(message)
{
  if (!empty_or_null(message))
    spad_log(message:message, name:'ftp_writeable_directories.log');
}

#
# Main
#

var commands_port, commands_socket, report, directories, depth_limit;

# Limit for dir crawler
depth_limit = 10;
debug_log(message:'Depth limit: ' + depth_limit);

commands_port = get_ftp_port(default: 21);

# Anonymous access to FTP is not possible
get_kb_item_or_exit('ftp/' + commands_port + '/anonymous');

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (safe_checks())
  # No corresponding audit message
  exit(0, "This plugin requires safe checks to be disabled.");

# Open connection to commands port
commands_socket = ftp_open_and_authenticate(
                   user:'anonymous',
                   pass:get_kb_item('ftp/password'),
                   port:commands_port
                 );

if (empty_or_null(commands_socket))
  audit(AUDIT_SOCK_FAIL, commands_port);

# Unfortunately we can not check writable directories based on
# permissions provided as part of FTP LIST command. Because:
# - MS Windows FTP Server (part of IIS) doesn't provide information
#   about permissions if "Directory Listing Style" setting is set 
#   to MS-DOS (default option).
# - There is no way to get current users' permissions / id / group
#   to match them with files' / folders' permissions.
# - FTP could be configured as anonymous read only, which doesn't
#   influence displayed permissions for files / folders but blocks
#   writting completely.
# We have to just try actual writting in order to be sure.
directories = dir_crawler(
                path:'/',
                commands_socket:commands_socket,
                depth_limit:depth_limit
              );

# Close FTP commands socket
ftp_close(socket:commands_socket);

# No writable directories found. FTP Server is not vulnerable
if (max_index(directories) < 1)
  audit(AUDIT_LISTEN_NOT_VULN, 'FTP Server', commands_port);

report = 'By writing on the remote FTP server, it was possible to ' +
  'gather the following list of writable directories:\n';

report += join(directories, sep:'\n');

debug_log(message:'Report Message: \n' + report);

# Set the KBs
replace_kb_item(name:'ftp/writeable_dir', value:directories[0]);
replace_kb_item(name:'ftp/tested_writeable_dir', value:directories[0]);
replace_kb_item(name:'ftp/' + commands_port + '/writeable_dir', value:directories[0]);
replace_kb_item(name:'ftp/' + commands_port + '/tested_writable_dir', value:directories[0]);

security_report_v4(
  port:commands_port,
  severity:SECURITY_WARNING,
  extra:report
);
