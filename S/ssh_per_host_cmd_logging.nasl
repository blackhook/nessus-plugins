#TRUSTED 182db78216439ca64cf255b430364573acd1c5b28e1d4c81556e8ebf59ce081139a1e46b9e4a7ba87eb3a0f7821174f0c98d312abadc12fbd45476a53a5302cbcc205d3050d5478aeaea7dd3a64768f6de97bc80f42a9022fb6b5ef5dd07d52fe48697a949117068d03e2de0892caad7fb9691085a52236afc3b7fd60036daa3a6fa14d37f1305404d6319cbceff8999fa680860b2d2ad38b8a3bf66c219a370dfb513e8b3221b2a89957334d221748e3a6e929f5a9792aeac6a50da24a8fedda353de5a25eaa4d1b62477e851f93e299dbdb719abcc0cdea20044a862cb8919b0efb4d59dbc51b594f56ed00d71d44ec58fd93a1f528c6d51c00bbe7c7428f67c29e0c9fefd73b516fef5dcce7f9168f7e05d4e2f28f95e64545ea935c2039a791eec9c802b81e2bfb4ff780105a39937ce828cd6c2cf8f193cac9ce47c67b5d37d92a6d034d84888136e207aad707f086f12998e79ca8aca42e5bc38f807cfb9ec6fc50327619d5fe3d78b9a4e2e64443adb3a32ad2d20bb79cb6cd7882c9ec004d5fecb432e6aba8483dc18c98008ae6c258a60cde9a82db3358ba5a1bab51befecbcd6841c07eb209ce06d32b3a609e5bfefac51b739ec07361c919d9c2af37bdf595202beabebdb39ffdc13012f63cba09f9d58f2aca5faa15af9e3b9ed22a6b0bfd7183a194d5db2e88a2c6fd13c911c63e0c142e29e6aec72588829c4
#TRUST-RSA-SHA256 54981dc2040d4b7aa2e85f5dbc2cebc4ce44f1bee8be1f1d58bdf98cab963cc72662dcaefa3ab96ac6ee32f1eef8014b96d0e627d74b1bedbba216a3140a5159a7870b1d33a76585b55b984acce514e0200c1645b9c536c5858a7031e2718e6c2551eafe2d0ac6dd0cc3eb8b98d9b6d8aaac4681be8b21b8721558e7d0cf44335fa0388039edb65372ae24a770859274265b799aeba382205fb733becb317c465d5c6e6af1df24151390c81eab1aa0ad24e0bf18f7aa74255327281012f40b50bbdd5051886fd13845a73c0f97ce521b6e6111210be5e6b20c07670addb3a4f464ce9712ab4660d36a40f4d035040b6facfdd5e635a46af83796130efe414bc635350c28f710597edb89c4412abbef18db293573d2bf5813d43c80799dbb4dcec1ae370c8a6b6b2c1fa359f4eb013b3f553e3670f4a374fd48cf9eca4caf82ef53ae51cce852614f1ef14874044c99122acd3e1687aeafba65fc17f9d06e67548e5b275a66bdb9ffd7f25c07b3b343d291851415df70ac79c35aec80bb73c470a5580e3a496c5680bfc9f0950267a1f31e4a94c351c6f8dc5e0c784886d99afa46c3f9a493ef1bd105d6a179aaf559c8f423383b5b6207ece0dbf97e95c91ffd3d21fb0b92137c617e4f84727efea11e94fdbc31bed7f53f3355258307dde8d1420fb8d9c315097a2f397da8198aa059fc7b9a82fe1313c9e9bb75326bec4361
#%NASL_MIN_LEVEL 80900

include("compat.inc");

if (description)
{
  script_id(168017);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_name(english:"SSH Per-Host Command Logging");
  script_summary(english:"Reports all commands run over SSH (does not depend on debug settings).");

  script_set_attribute(attribute:"synopsis", value:
"If the 'Always report SSH commands' advanced preference is selected
in the scan policy, this plugin will report all commands run over SSH
on the host in a machine readable format.");
  script_set_attribute(attribute:"description", value:
"If the 'Always report SSH commands' advanced preference is selected
in the scan policy, this plugin will report all commands run over SSH
on the host in a machine readable format.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");
  script_require_keys("global_settings/always_log_ssh_commands");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("global_settings/always_log_ssh_commands");

# initialize an empty table if nothing has been logged so second call doesn't fail
query_scratchpad("CREATE TABLE IF NOT EXISTS ssh_cmd_log_json (" +
                   "id        INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                   "json_text TEXT, " +
                   "host      TEXT, " +
                   "time      DATETIME DEFAULT current_timestamp );");
rows = query_scratchpad("SELECT time, json_text FROM ssh_cmd_log_json where host = ? order by time;", get_host_name());

if(!rows || len(rows) == 0)
  exit(0, "No SSH commands were executed on the host.");

ssh_cmd_data = '';
foreach var row (rows)
  ssh_cmd_data +=  "[" + row['time'] + "] " + row["json_text"] + ',\n';

ssh_cmd_data = substr(ssh_cmd_data, 0, strlen(ssh_cmd_data) - 3);

cmd_attachment = {
  "type": "text/json",
  "name": "ssh_commands_run.json",
  "value": ssh_cmd_data
};

security_report_with_attachments(
  port:0,
  level:0,
  extra:'\nThe SSH commands run on this host have been attached:\n\n',
  attachments:[cmd_attachment]
);
