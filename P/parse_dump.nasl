#TRUSTED 4436c742b277bbf005ed7cee2b7adb57a24ce643fd989ce3ebd4e4c17f72986a41b9ab2d60ff9fcbff80cb36f3d693e2bf5ddd030db43c84c333c18277f791cddf813a7f8c18cbe120ff602880d9e8f0993718aeb12b699af12c84300600ea81fd11336413188726b93ea05bff077ae821ac1f768b68cbb3f88724d545b6678f1e710531a40968262956eea6f178350cb92bafb9e853bcd0629021fd9bf3e774b32ba1a5a90466217d09e1a2ca55913e71ef8c6e34fad783185a713ef1494a757e80d2d1148e8db2d089a1f315690f8869399cbd372d2f395438c49c891ea28ad2535695a5adbe616ce9fe1d9e25cdd8e74b24187af9bb1f8a9b89a46ebd219a0f204f6f81c956dc2d5cc9fcbb9cd4e0799db96c63470fb99f500b2768fe08d44de0e1c4389a4cd8edd464b5a2173962a8b60944a27e6b0ca1076a0bf8ae673ceb93422b47f28cf89b3a72b8bad5804ad07f3114d549e97632d42d2028f9599eb75e1e3bf1f15e114205fbfaa9b6fb0dbfbd05c8f747da6654bba00a6cb902053aeeb893d7f9c1e39895ff5cf30872a0f636e3d65a074a1ad45d206fc0d5ade8c80ea51db888852988db465fc82da9adfdb0ec06c0fe210bc431bcc5c5d74189d25e5bc1773c93910f5e30e1c0f2db28fb1428ebdac7f9144f6260b7bf587e69925eeef4995658b9accc036906344371ac2ddd675baefdd264e26f7d430339ac
#TRUST-RSA-SHA256 59df5914d2a4517783888ec4dd98ac1579e2b0c94e285c3fb37b04d1227b8838ef95be3e55960cd37f9697318781e70cf5dcffb27e21fb0b0cf3276c7230d34be7809a299ae68d3d53ba48e289c3884c3d5c3324de82b84a9373c861ff2a70c0c262b3ff1db9fb8f7d1e03f9d4a4e810299bb179185d51532015ce5b0c8502972ad7acf5519ca9e819efc58e73053913944f375db7d747d89c897ad032ddd0801fcbcc4bc0a3ea32565c22a51426c32363af6fd10124035ba7adf4a727e68f85b44c18713efc44edede98a9a794069ffddb07bbcdef77ce352567cfe7c24ec78abd1c61cc024616c6109101a0caf9f1e72504c4a71735c6dd948d6592146a2e3cc012f42e2766dd9a265c7ff4f760addfcc30deab14d3766aec3690c81d11b24075902b393c68c833cbb6d9f7aa7dd392bcdcee1f6ce87a4a0cf65274977176a0442688d56476538b1fafea6eae7f6043be6c5694fa6956a82cac97fb5ec94743c30ea4811ccfab86ee5d1166561c8f3cdd1a07f1333969fb04ae7aee08d8f3ae423d9e1fb4d55252348cd3d0cd4de396217de4de6c3312385c834cf6dd4464d674e934715f0ba21df790d0d9c7166d6e480ac2f18a5acc8499b682ddcd81faa417d52e5c76ccc7f10f5d6d1e1fa17987251a83b25568b522c6a073c2ee8539681ddf3397137345bb5b5dd2b3b1ee8ed6ad27db81bc4b4217067b4a9694efbb1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117530);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_name(english: "Errors in nessusd.dump");
  script_summary(english:"Parses out errors occuring in the nessusd.dump file.");
  script_set_attribute(attribute:"synopsis", value:
"This plugin parses information from the nessusd.dump log
file and reports on errors.");
  script_set_attribute(attribute:"description", value:
"This plugin parses information from the nessusd.dump log
file and reports on errors.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");

  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_timeout(5*60);
  script_require_keys("global_settings/enable_plugin_debugging");
  script_exclude_keys("Host/msp_scanner");

  exit(0);
}

include("datetime.inc");
include("global_settings.inc");
include("nessusd_logs.inc");
include("nessusd_product_info.inc");

get_kb_item_or_exit('global_settings/enable_plugin_debugging');

# Suppress plugin on T.io
if (get_kb_item("Host/msp_scanner"))
{
  exit(0, "This plugin does not run on T.io scanner systems.");
}

# This is here to prevent license issues on SC and TIO.
# Because this plugin could count against SC/TIO license we makes
# sure that ports have been detected on the target client which
# tells us the target is a valid asset
tcp_ports = get_kb_list("Ports/tcp/*");
udp_ports = get_kb_list("Ports/udp/*");
if (!nessusd_is_agent() && isnull(tcp_ports) && isnull(udp_ports))
{
  exit(0, "No ports available, port detection prevents reporting on targets with no host-based scan results.");
}

host_dict = make_array();

MAX_ATTACHMENT_SIZE = 1024*1024*35;

nessus_dir = nessus_get_dir(N_LOG_DIR);
dirslash = '/';
if(platform() == 'WINDOWS')
  dirslash = "\";

dumpfile = nessus_dir + dirslash + 'nessusd.dump';
messages = nessus_dir + dirslash + 'nessusd.messages';

start = '';
scan_uuid = get_preference("report_task_id");
if(isnull(scan_uuid))
  exit(0, "This plugin is not for use with command line scans.");

if(isnull(file_stat(messages)))
    exit(1, "The nessus messages log at: " + messages + ", does not exist.");

pid_tid_regex = NESSUSD_LOG_TID_PID_REGEX;
if(is_nessusd_pre_7_2())
{
  pid_tid_regex = NESSUSD_LOG_PRE_7_2_TID_PID_REGEX;
}

fd_message = file_open(name:messages, mode:'r');

# Loops through the nessusd.messages files storing target hosts by pid/tid pairs
# and collecting scan start times.  The scan id is used to identify the current
# and the current scan start time is stored to help filter dump messages.
last_buf = '';
while ( message_contents = file_read(fp:fd_message, length:1024) )
{
  message_contents = message_contents;

  messages = split(last_buf + message_contents);
  message_count = max_index(messages);

  last_buf = '';
  # We don't save the last line segment or it won't get processed and only have to
  # bring over the last segment as a line fragment if the part of the stream we
  # read is not line terminated.
  if(strlen(message_contents) == 1024 && message_contents[strlen(message_contents)-1] != '\n')
  {
    message_count --;
    last_buf = messages[message_count];
  }

  for(i = 0; i < message_count; i++)
  {
    message = messages[i];
    if( scan_uuid >< message)
    {
      if("starts a new scan" >< message || "starting with Target" >< message)
      {
        start_match = pregmatch(pattern:NESSUSD_LOG_TIME_REGEX, string:message);
        if(start_match && start_match[1])
          start = start_match[1];
      }

      if(start)
      {
        pid_tid_match = pregmatch(pattern:pid_tid_regex, string:message);

        if(pid_tid_match && pid_tid_match[1] && pid_tid_match[2])
          host_dict[pid_tid_match[1]] = pid_tid_match[2];
      }
    }
  }
}
file_close(fd_message);
start_unixtime = logtime_to_unixtime(timestr:start);
if(isnull(start_unixtime))
  exit(0, "No valid start time for this scan was found in the messages log." );

if(isnull(file_stat(dumpfile)))
    exit(1, "The nessus dump log at: " + messages + ", does not exist.");

fd_dump = file_open(name:dumpfile, mode:'r');
dumps = '';
dump_size = 0;
dumping_plugins = make_array();
collect = FALSE;

# Loops through the nessusd.dump log and starts collecting messages
# at the start of the current scan as determined by the prior loop
# through nessusd.messages.  Dump messages are mapped by tid/pid to their
# target host and are filtered by scan id.
last_buf = '';
while( dump_contents = file_read(fp:fd_dump, length:1024) )
{
  dump_contents = dump_contents;

  lines = split(last_buf + dump_contents);
  dump_count = max_index(lines);

  last_buf = '';
  # We don't save the last line segment or it won't get processed and only have to
  # bring over the last segment as a line fragment if the part of the stream we
  # read is not line terminated.
  if(strlen(dump_contents) == 1024 && dump_contents[strlen(dump_contents)-1] != '\n')
  {
    dump_count --;
    last_buf = lines[dump_count];
  }

  for(i = 0; i < dump_count; i++)
  {
    line = lines[i];

    if(!collect)
    {
      datematch = pregmatch(pattern:NESSUSD_LOG_TIME_REGEX, string:line);
      if(datematch && datematch[1])
        date = datematch[1];
      else
        continue;

      time = logtime_to_unixtime(timestr:date);
      if( !isnull(time) && time >= start_unixtime )
        collect = TRUE;
    }

    if(collect)
    {
      dump_has_scan_id = FALSE;
      plugin_match = pregmatch(pattern:NESSUSD_DUMP_LOG_REGEX, string:line);
      if(plugin_match && plugin_match[1] && plugin_match[2])
      {
        scan_id_match = pregmatch(pattern:"\[scan=([a-z0-9-]+)\]", string:line);
        if(scan_id_match && scan_id_match[1])
          dump_has_scan_id = TRUE;

        host = host_dict[plugin_match[1]];
        if(!host)
        {
          host = pregmatch(pattern:"\[target=([0-9.]+)\]", string:line);
            if(host && host[1])
              host = host[1];
            else
              continue;
        }

        #Prior to Nessus 7.2, nessusd.dump log entries did not have enough information to separate
        #messages from concurrent scans against the same host.
        if(host == get_host_ip() && (!dump_has_scan_id || scan_id_match[1] == scan_uuid))
        {
          plugin = plugin_match[2];
          if(dumping_plugins[plugin])
            dumping_plugins[plugin]++;
          else
            dumping_plugins[plugin] = 1;

          if("Recursive foreach" >< line)
            report_xml_tag(tag:"recursive-foreach", value:plugin);
          if("Bad enumerator" >< line)
            report_xml_tag(tag:"bad-enumerator", value:plugin);

          dump_size += strlen(line);
          if(dump_size <= MAX_ATTACHMENT_SIZE)
              dumps += line;
        }
      }
    }
  }
}
file_close(fd_dump);

report = '';
if(max_index(keys(dumping_plugins)))
{
  report = 'The nessusd.dump log file contained errors from the following plugins:\n\n';
  foreach plugin (keys(dumping_plugins))
  {
    plural = '';
    num = dumping_plugins[plugin];
    if(num > 1)
      plural = 's';
    report += '  - '+plugin+' reported '+num+ ' error'+plural+'\n';
  }

  if(dump_size > MAX_ATTACHMENT_SIZE)
      report += '\nnote: The dump file has been truncated to 35MB due to its size.';

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text";
  attachments[0]["name"] = "nessusd.dump";
  attachments[0]["value"] = dumps;

  security_report_with_attachments(
          port        : 0,
          level       : 0,
          extra       : report,
          attachments : attachments
          );
}
