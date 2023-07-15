#TRUSTED 197d0abbdc527feec14ddda130758639e358987184399a46d8cd4a7f1b356eec7bdd030ee7770d4a80633cf60c29a36554ed511c6726d73e2ee44188465fe2ba0c7872cb73ed610c5d22ec779ded278d385198cb5f3af9a71c97a8a60c15274d302837bf3a2860de8d5edcfc8711297bb001004e0887aa238de243d191336de1754f4d849808701fbecb154eb93ff201158b8e44c9dd6883f0219f7a6e36fbda5cddc39b6b5796513b4a4873800739bac0fe2634038698ee937042f64db4d470595966f5050ed213536e30dcf635370611c5bd4a0d0bac167cbc5e5d8d54579a9df333f5ddb4ce573f6b0304fb4cfea2e8dea7ef943c7539bec75ebfca436dd399ae05b7b914e42f17818f4a2c8d00effb48cb709550f2250e36e298eba01e1b5821fcf4561bb6cb64561570bfe227b1c458d8dbd3bd06586f65e3c3e11ef67f72bfb426b1dd5a14d11a78ed169d411009b91a7806d88c6d01ddb7834059afdcdcfcd96ea93edce4a61910bb108e52f69d90f937c58df86ed0925dc6e007c89993a7186943fea684224762f13e2592269632f0fedbf2ba2a10378ce31f91f0a1e8a5a61089694ec4ba54b6a90ed399a56e3e95c818fbc3ff282ed4ab2236646b618399d28424828c97fb042a3ed2e77a055b2c81c39e5aebb9ffa5d66e6d61698e5efc5f8027fe8908adb03d74ba763570e5e67dedcedb8cee9c9b413656f03a
#TRUST-RSA-SHA256 1f2fc9fd03391ceb3387cd49182217ccee3ef4c80da684b8e3c9cd65b24b1f4ed0ae5238b9385b5cd8b2502c99be07a5ee6f2aeb8d6fa6e554d1f6620005b212885e973d042ca285ed8af0c8446268a983736b8535a4d97413a488432fb416ea24051877b431f1f3cf74f2d454b25155c7bc3a5ea11550f20b0469650afa118ebe0a42a637970b6b625893d98676ae127cba10ff56499d2dbf7fbcced109c698e5b7e5a1d80b63fda0f65daeda46aca266c75a30b0e7c7d4e61622903b8270ea304db5cf2a7003ff10ee500eb393c93aebe2cecab115aa765e66e8f09697819bab84c16225be6d3b78cb8bb2d41dfdd69017127f986b77ec83258bb23d97637ed79a5ff49129056c58a8c974794a4f823f32ce3bc7dc3295127599fa832d9d8378e3235bf4cfcfbeac85b3848ff6f8c0cb7746868d3100cb508f84c2e7852433a3e19578ae12b960eee212952bdecd0b2a887b99bdb015b502a7cc1b9cc54d77caf42640ffbec1388a16124988338cae7714e2c547d0d43051065d3aae82be1d96b55c7784cd28a5bf50abfb4ebe432fda5c1a92ff7b139a065ea2d9663bb5bb5da4fe1d64db613f54f2d5d401dde904badf6287b7cf151622a92e5d15ddb401793b3cec1c880cb66ee5f5ec88743bae6fda11bbcd5303c84fe24be40f02986119277b9d8d68a0e733bcbc6c7b77347ac9440cf5f5f05ae66310e55dea2143a5

include("compat.inc");

if (description)
{
  script_id(100158);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_name(english:"SSH Combined Host Command Logging (Plugin Debugging)");
  script_summary(english:"Writes ssh command log for host to combined log on scanner host.");

  script_set_attribute(attribute:"synopsis", value:
"If plugin debugging is enabled, this plugin writes the SSH commands
run on the host to a combined log file in a machine readable format.");
  script_set_attribute(attribute:"description", value:
"If plugin debugging is enabled, this plugin writes the SSH commands
run on the host to a combined log file in a machine readable format.
This log file resides on the scanner host itself.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_require_keys("global_settings/enable_plugin_debugging");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("global_settings/enable_plugin_debugging");

# initialize an empty table if nothing has been logged so second call doesn't fail
query_scratchpad("CREATE TABLE IF NOT EXISTS ssh_cmd_log_json (" +
                   "id        INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                   "json_text TEXT, " +
                   "host      TEXT, " +
                   "time      DATETIME DEFAULT current_timestamp );");
rows = query_scratchpad("SELECT time, json_text FROM ssh_cmd_log_json order by time");

if(!rows || len(rows) == 0)
  exit(0, "No ssh log entries to write.");

SSH_LOG_UUID_KEY = "ssh_log_uuid";

first_entry = FALSE;

mutex_lock(SSH_LOG_UUID_KEY);
  uuid = get_global_kb_item(SSH_LOG_UUID_KEY);
  if (isnull(uuid))
  {
    first_entry = TRUE;
    uuid = generate_uuid();
    set_global_kb_item(name: SSH_LOG_UUID_KEY, value: uuid);
  }
mutex_unlock(SSH_LOG_UUID_KEY);

scanner_os = platform();
path_separator = "/";
if (scanner_os == "WINDOWS")
  path_separator = "\";

log_file = get_tmp_dir() + path_separator + 'ssh_commands-' + uuid + '.log';

file_data = '';
if(!first_entry) file_data += ',\n';

foreach var row (rows)
  file_data +=  "[" + row['time'] + "] " + row["json_text"] + ',\n';

file_data = substr(file_data, 0, strlen(file_data) - 3);

fd = file_open(name: log_file, mode: 'a');
file_write(fp: fd, data: file_data);
file_close(fd);

security_note(port:0, extra:'\nCombined log file location :\n\n  ' + log_file + '\n');
