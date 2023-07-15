#TRUSTED 8271adffc4bea124ceda71338a7e81de343d4b52c95eb8691f7fd83f333d49953d9448fa2c0101ef2e47f180b7c0a1c881e3875b2016abc0f02f35e014a176c11f3c8ae9ba962dec8287543082240b09f7298349da4dc2811971822cd04f8e8148133d1924ce0291a3fbdab6e3c4c702d51b9d6df30407fb4c660091659307ddd633318851bbe991acedeb4a6ee4c8da33342fb7fe4cc600a1b5cdcd8d6e41cf53fe6c3bf50380591e9dd3df0036f1ffd523738695feade43c86540a31885d717f690108c3c4359b554798f67a2fa6f1922d7c7f45ae72afceea1a67b5e5cd8afe85a8c2e90abf6fc6ed483a4a37210c16371c1cbdf586ae6aa358f8bd124fca453afaf02a4a92307183cd65869f4533f1d054e4a4586eb4ed000b9989794547dcd8077e8e879b9ce0990c3b4937caa2ab3786f33849efec72410f6d794853c4a24beb86531ddd4dc76a6c4f4f258a430d8f4ac45db9216d5478fa1f296fd93f7d1fd7d58cb7d137a4576f52a8900b4eb85bfd76252f95c24bfe9e5b7089b82df6a4cf5fc79eb9754d3c5b9585ba859a16e6df6e84376a87e59aaa354d05e57a69a5ab17206d7103a2e22b7ee6bacb412d17c4fd7ef3f3c9887056267a21aad3237dfcc681d04efcea3ea254dc120dbaeea08a00c43222f78108c91369bab9e8c2beb3d334b5f5f95d2273d643fb8f91cf57bc997f3b617a5af9d29fdb2e8afb
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(34098);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_name(english: "BIOS Info (SSH)");
  script_summary(english: "Get BIOS info using command line");

  script_set_attribute(attribute:"synopsis", value: "BIOS info could be read.");
  script_set_attribute(attribute:"description", value: "Using SMBIOS and UEFI, it was possible to get BIOS info.");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value: "None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "General");

  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22, "nessus/product/agent");
  script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate");
  exit(0);
}
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
{
  enable_ssh_wrappers();
}
else
{
  disable_ssh_wrappers();
}

# do ALL of the KB values we know how to fetch exist?
if ( get_kb_item("BIOS/Vendor") &&
     get_kb_item("BIOS/Version") &&
     get_kb_item("BIOS/ReleaseDate") &&
     get_kb_item("BIOS/SecureBoot") )
{
  # ALL of the KB values we know how to fetch exist, exit
  exit(0, "BIOS information already collected according to KB items." );
}


function get_uuid_from_buf(buf)
{
  var uuid_regex, match;
  uuid_regex = "^(\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b)$";
  if (!empty_or_null(buf))
  {
    match = pregmatch(pattern:uuid_regex, string:buf);
    if (empty_or_null(match)) return NULL;
    else return match[1];
  }
  return NULL;
}


# We may support other protocols here
info_connect(exit_on_fail:TRUE);

# I planned initialy to run 
#  dmidecode -s bios-vendor 
#  dmidecode -s bios-version 
#  dmidecode -s bios-release-date
# Unfortunately, not all versions of dmidecode support the "-s" option.
# dmidecode -t 0 (which gives only BIOS information) is not supported
# everywhere either. So we have to parse the whole output.

# Work around broken $PATH
dirs = make_list( "", "/usr/sbin/", "/usr/local/sbin/", "/sbin/");

keys = make_list("Vendor", "Version", "Release Date");
values = make_list();
found = 0;

foreach d (dirs)
{
  cmd = 'LC_ALL=C ' + d + 'dmidecode';
  spad_log(message:'Trying to run dmidecode with command: ' + obj_rep(cmd) + '\n');
  buf = info_send_cmd(cmd: cmd);
  if ('BIOS Information' >< buf)
  {
    lines = split(buf, keep: 0);
    drop_flag = 1;
    foreach l (lines)
    {
      if (preg(string: l, pattern: '^BIOS Information'))
      {
        drop_flag = 0;
        continue;
      }
      else
      {
        if(preg(string: l, pattern: '^[A-Z]'))
        {
          drop_flag = 1;
        }
      }
      if (drop_flag)
      {
        continue;
      }

      foreach k (keys)
      {
        pat = '^[ \t]+' + k + '[ \t]*:[  \t]*([^ \t].*)';
        v = pregmatch(string: l, pattern: pat);
        if (! isnull(v))
        {
          values[k] = v[1];
          found++;
        }
      }
    }
  }
  if (found > 0)
  {
    break;
  }
}

#
# UEFI spec
# http://www.uefi.org/sites/default/files/resources/UEFI%20Spec%202_7_A%20Sept%206.pdf
# SecureBoot BS, RT Whether the platform firmware is operating in Secure boot mode (1) or not (0). All other values are reserved. Should be treated as read-only.
# 
# Using * because sometimes vendors overload the global variable ID
# /sys/firmware/efi/efivars/SecureBoot-*
# if it exist:
# 06 00 00 00 01  -> 4 bytes for 32 bit access mask then 1 byte value (enabled)
# 06 00 00 00 00  -> 4 bytes for 32 bit access mask then 1 byte value (disabled)
#
dirs = make_list( "", "/bin/", "/usr/bin/", "/usr/local/bin/" );
bootSecure = "unknown";
foreach d (dirs)
{
  # 06 00 00 00 01
  cmd  = 'LC_ALL=C 2>/dev/null ' + d + 'od -An -t x1 /sys/firmware/efi/efivars/SecureBoot-*';
  cmd += ' || ';
  cmd += 'LC_ALL=C 2>/dev/null ' + d + 'hexdump -ve \'10/1 "%02x " "\n" \' /sys/firmware/efi/efivars/SecureBoot-*';
  cmd += ' || ';
  cmd += 'LC_ALL=C [ ! -d /sys/firmware/efi ] && echo "06 00 00 00 00"';
  otherBuf = info_send_cmd(cmd: cmd);
  spad_log(message:'Checking UEFI secureboot with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(otherBuf) + '\n');
  lines = split(otherBuf, keep: 0);
  foreach l (lines)
  {
    # od or hexdump both report this format for enable
    if ( preg( string:tolower(l), pattern:"06 00 00 00 01" ) )
    {
      bootSecure = "enabled";
      break;
    }
    # od or hexdump both report this format for disabled
    if ( preg( string:tolower(l), pattern:"06 00 00 00 00" ) )
    {
      bootSecure = "disabled";
      break;
    }
  }
  if ( bootSecure != "unknown" )
  {
    # we have the answer stop looking
    replace_kb_item(name: 'BIOS/SecureBoot', value: bootSecure);
    break;
  }
}

# Parse UUID from dmidecode output
uuid = pgrep(pattern:'^[\t ]*UUID[ \t]*:', string:buf);
if ( !isnull(uuid) )
{
  pat = '^[ \t]+UUID[ \t]*:[  \t]*([^ \t].*)';
  v = pregmatch(string: uuid, pattern: pat);
  if ( !isnull(v) )
  {
    uuid = v[1];
  }
  else
  {
    uuid = NULL;
  }
}

#
# Try to use alternate methods to obtain Version, Vendor, Release Date, UUID incase dmidecode failed
#
# UUID from /sys/hypervisor/uuid
if (isnull(uuid))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/hypervisor/uuid';
  uuidBuf = info_send_cmd(cmd: cmd);
  spad_log(message:'Reading uuid with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(uuidBuf) + '\n');
  uuid = get_uuid_from_buf(buf: uuidBuf);
  if (!isnull(uuid) && strlen(uuid) > 0) found++;
}

# UUID from /sys/devices/virtual/dmi/id/product_uuid
if (isnull(uuid))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/product_uuid';
  uuidBuf = info_send_cmd(cmd: cmd);
  spad_log(message:'Reading uuid with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(uuidBuf) + '\n');
  uuid = get_uuid_from_buf(buf: uuidBuf);
  if (!isnull(uuid) && strlen(uuid) > 0) found++;
}

# Vendor from /sys/devices/virtual/dmi/id/sys_vendor
if (empty_or_null(values) || empty_or_null(values['Vendor']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/sys_vendor';
  vendor = info_send_cmd(cmd: cmd);
  spad_log(message:'Reading vendor with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(vendor) + '\n');
  vendor = strip(vendor, pattern:'\n');
  if (!isnull(vendor) && strlen(vendor) > 0)
  {
    values['Vendor'] = vendor;
    found++;
  }
}

# Version from 
if (empty_or_null(values) || empty_or_null(values['Version']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/product_version';
  version = info_send_cmd(cmd: cmd);
  spad_log(message:'Reading version with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(version) + '\n');
  version = strip(version, pattern:'\n');
  if (!isnull(version) && strlen(version) > 0)
  {
    values['Version'] = version;
    found++;
  }
}

# Release Date from /sys/devices/virtual/dmi/id/bios_date
if (empty_or_null(values) || empty_or_null(values['Release Date']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/bios_date';
  bios_date = info_send_cmd(cmd: cmd);
  spad_log(message:'Reading bios date with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(bios_date) + '\n');
  bios_date = strip(bios_date, pattern:'\n');
  if (!isnull(bios_date) && strlen(bios_date) > 0)
  {
    values['Release Date'] = bios_date;
    found++;
  }
}

if(info_t == INFO_SSH)
{
  ssh_close_connection();
}

if (found || 'BIOS Information' >< buf || 'System Information' >< buf)
{
  replace_kb_item(name: 'Host/dmidecode', value: buf);
}

if (!found)
{
  audit( AUDIT_NOT_DETECT, "BIOS info" );
}

report = "";
foreach k (keys(values))
{
  k2 = str_replace(string: k, find: " ", replace: "");
  if ( !empty_or_null(k2) && !empty_or_null(values[k]) )
  {
    replace_kb_item(name: "BIOS/" + k2, value: values[k]);
    report = report + k + crap(data: ' ', length: 12 - strlen(k)) + ' : ' + values[k] + '\n';
  }
}

if ( !isnull(uuid) )
{
  report = report + "UUID" + crap(data: ' ', length: 12 - strlen("UUID")) + ' : ' + uuid + '\n';

  if ( defined_func('report_xml_tag') )
  {
    report_xml_tag(tag:'bios-uuid', value:uuid);
    set_kb_item(name:"Host/Tags/report/bios-uuid", value:uuid);
  }
}

if ( !empty_or_null( report ) )
{
  report = report + "Secure boot" + crap(data: ' ', length: 12 - strlen("Secure boot")) + ' : ' + bootSecure + '\n';
  security_report_v4(port: 0, severity:SECURITY_NOTE, extra:report);
}
