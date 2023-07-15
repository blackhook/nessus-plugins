#TRUSTED 517946a0d8391a5a4b1f508188d33badaa079e449767b8c33504298e1f11149a72f30965c7b48e6280cc07a3b92067601974f608b43573b5823ca238689fe930d7d995dcb3d2d25a9e0edf6b86564a855397f238458ad08184c4a15872e130c4f1b186ccbee0d9667ecdbfc69e95ed758f01a80ca6a4ddfdf102f324d47a6aadd0dd2074fc72fd4ada6781aa389e16057ea1093028cb3c8ceb3b97fa2a08703d853967bbff7654c4ed5e4b2e720fc0081e09b022d179ef87f0495fd863bb1396700471546a34e1ad553e8b696b3bb549d05650078ddfa32ef6a5fae5c9cbb73027a4de0372a1bf9702193d8d0f1b1db1cf93bfdcd68e462e5fbc29dada14f9b6e1bdb54e696daf3ee7aaebfcafcbcca37af64d5c7bc0b602c1f0651be2967438c6c8230f2a093e78bd34cd64db3c86da38ce2d2a4b8398c99b151d38caeb4b53c69dc49edb3243b060ace2dab3b292e506e731ec3d1d00560a7855ea8d1d55661b5bbe4d060e7900c9b266fcc676b44f7ea6662dde27bdee21914a27df0e8d7fc5e9870e58e8292184232e48b9d5821a91d614f680bcd2c5a90d095e4a17c3b708bb99c9938e92fc825196b9dfece6bdf66ce5981dbe021cb083c0e794a58705a69cab68d843d792e3a0edf4395a74c723b996228bcd2abe87d7198310eea068115b36ab9bb1067a940aa12d4a43916112cb7a47af2e81d884442a2f8df60891
#TRUST-RSA-SHA256 37a23286d116bcf849e6341f399826d19ae23721d843cfbae1776cee134e926cf838baf40628cdefdbe698826e9b678cf2d62dd7e5bd1acbe128c62acae555fa0cb357f71d7df9f75a7a6d648425edb5fa81ce9a87e4d5c6a74d2aa1843e25454983c3f3bdb3f1fe3c53ceb7b92ddd7b5ddd4ae5bcf2b321882093e6c1355800c161bd26fb9ffc275b2df63929bd8eb91f16f7951468ce1601bf5e21c1b00ee7b78110f23ccf318f663e753775cabe7611728261c891b39d9b6b4f67aa4fc1829a61f1710a10f3e9cb924741bcef9c4f4f869522a12b36e23f1e134b1c61914040b67b5d65d04a945e59605f9ed5cc72e499c5907d17351e707977a3c6c68921a44c9ef02cf4ae96a7dca48461be077ac6a571ca9595e2c890e26da209a0ca5a74f13dbc502969b576aa1fdd59870e4ed074b9cfc97c68e54247b6a29ba75a76f316ac4395603dfeee3f31e5341c0a49f7d54ad68b5b698511282225208acb5abb5fef8be56cccd31431eee087eb978c9ac8f33db7d966bc32c14a8612b510bb0f989a9c1c8a33efe4aa8a83c1c930ef031edf7f954af18f557a3808dfabbb7c991de8733a142562c5e7d213c9a906665167eafef9bcdd0e6de5765861e5328c6832361f8a5b71f1df6e38c3c83b3f68db97c7f504417594d5e714a36dac17f340891be8eb8ef87778f51cbb578d04b9595fdad03e63e6bddc0d4bfddc433369
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(58501);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"iTunes Mobile iOS Device Backup Enumeration (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is used to backup data from a mobile
device.");
  script_set_attribute(attribute:"description", value:
"The iTunes install on the remote Mac OS X host is used by at least
one user to backup data from a mobile iOS device, such as an iPhone,
iPad, or iPod touch.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1766");
  script_set_attribute(attribute:"solution", value:
"Make sure that backup of mobile devices agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_itunes_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function parse_device_info(data)
{
  local_var section, value, idx_start, idx_end, datakey;
  local_var device_data, datakeys;

  device_data = make_array();

  datakeys = make_list(
    'Device Name',
    'Last Backup Date',
    'Product Type',
    'Product Version',
    'Serial Number'
  );

  foreach datakey (datakeys)
  {
    section = '';
    value = NULL;
    # Extract each relevant key/value pair
    idx_start = stridx(data, '<key>'+datakey+'</key>');
    if (datakey == 'Last Backup Date')
      idx_end = stridx(data, '</date>', idx_start);
    else
      idx_end = stridx(data, '</string>', idx_start);
    if ((idx_start >= 0) && (idx_end > idx_start))
    {
      section = substr(data, idx_start, idx_end);
      section = chomp(section);
    }

    # Extract the vale from the key/value pair
    if (strlen(section) > 0)
    {
      if (datakey == 'Last Backup Date')
      {
        idx_start = stridx(section, '<date>');
        if (idx_start >= 0)
        {
          value = substr(section, idx_start);
          value -= '<date>';
          value -= '<';
        }
      }
      else
      {
        idx_start = stridx(section, '<string>');
        if (idx_start >= 0)
        {
          value = substr(section, idx_start);
          value -= '<string>';
          value -= '<';
        }
      }
    }
    if (!isnull(value))
    {
      device_data[datakey] = value;
    }
  }
  if (max_index(keys(device_data))) return device_data;
  else return NULL;
}

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');

os = get_kb_item('Host/MacOSX/Version');
if (!os) exit(0, 'The host does not appear to be running Mac OS X.');

if (isnull(get_kb_item('installed_sw/iTunes'))) exit(0, 'iTunes doesn\'t appear to be installed on the remote host.');

info_connect();

invalid_path = FALSE;
template_error = FALSE;

# For each user, look for backups in
# Library/Application Support/MobileSync/Backup
numdevices = 0;
info = NULL;
cmd = '(echo ; /usr/bin/dscl . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID | awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -d "$Home"/Library/Application\\ Support/MobileSync/Backup/ && echo "$Home"/Library/Application\\ Support/MobileSync/Backup/*; done';

result = info_send_cmd(cmd:cmd);
if (!isnull(result))
{
  lines = split(result, keep:FALSE);
  foreach line (lines)
  {
    devicehash = NULL;
    if ('Library/Application Support/MobileSync/Backup/' >< line)
    {
      # Replace ' /' with ';/' to make it easier to split up the hashes
      # into a list
      line = str_replace(string:line, find:' /', replace:';/');
      hashlist = split(line, sep:';', keep:FALSE);
      if (!isnull(hashlist))
      {
        for (i=0; i<max_index(hashlist); i++)
        {
          data = NULL;
          plistfile = hashlist[i] + '/Info.plist';
          plistfile = str_replace(string:plistfile, find:'Application Support', replace:'Application\\ Support');
          match = pregmatch(pattern:"(^.*)Library/Application\\ Support/MobileSync/Backup/(.*$)", string:plistfile);
          if(isnull(match) || isnull(match[1]) || isnull(match[2]))
            continue;
          cmd = "cat $1$Library/Application\ Support/MobileSync/Backup/$2$";
          args = [match[1], match[2]];

          # Parse the data in the plist file
          data = run_cmd_template(template:cmd, args:args);
          if(data["error"] != HLF_OK)
          {
            if(data["error"] == HLF_INVALID)
              invalid_path = TRUE;
            else
              template_error = TRUE;
            continue;
          }
          data = data["data"];
          if (!isnull(data) && '<?xml version=' >< data)
          {
            ret = parse_device_info(data:data);

            if (!isnull(ret))
            {
              numdevices++;
              # Build the report
              info += '\n  File path : ' + plistfile;
              info +=
                '\n    Device name      : ' + ret['Device Name'] +
                '\n    Product type     : ' + ret['Product Type'] +
                '\n    Product version  : ' + ret['Product Version'] +
                '\n    Serial number    : ' + ret['Serial Number'] +
                '\n    Last backup date : ' + ret['Last Backup Date'] + '\n';
            }
          }
          if (numdevices && !thorough_tests) break;
        }
      }
    }
  }
}

if (info_t == INFO_SSH)
  ssh_close_connection();

errors = "";
if(invalid_path)
  errors += '\n  One or more path names contained invalid characters.';

if(template_error)
  errors += '\n  An error occurred due to a command template mismatch.';

if (errors != '')
  errors = '\nResults may not be complete due to the following errors : ' + errors + '\n';

if (!isnull(info))
{
  if (report_verbosity > 0)
  {
    if (numdevices > 1)
    {
      a = 'Backups';
      s = 's were detected';
    }
    else
    {
      a = 'A backup';
      s = ' was detected';
    }
    report =
      '\n' + a + ' for the following mobile device' + s + ' :\n' +
      info +
      '\n' + errors;
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
else exit(0, 'No backups were detected for mobile iOS devices on the remote host.' + errors);
