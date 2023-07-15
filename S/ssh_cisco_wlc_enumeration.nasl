#TRUSTED 80056e4cf9d70afb5937fb671bbcbb4498b347401de183bb83c421ea47699c566ab5e9bb2973c2c06e4e512b40a689e90cbbb6de3eac8a2f0974bdbf2dc60dab14df9c41fb9f6120581f8e2045cd28d6324b313c8566155e978784aad1b2a2faab2244ab01a20c285bc10e70f672c8cde8421616a21aa0fd965d7e7a6f6e764a2925f1862966e5948e9d1ff7735893d6e763a43dcfcf89b5dca81dc0abb7804b59832922dbad14e9f2c4d657dfa1d2620f75ab25ca13fccc1ccaa8db7160659776203a6cd8f071aff584e20aec5f5a7fc933d76d09f8f5b05cc505aaab849212e431acff02d49b80ad23d124d97be5799a1aa313cc707d3f341243f5f553b91422b779bd3dfabc467baca906c75abd316c4c7b716b246594c0c5d0960b942cdd2021fef498b11d180f9c785bf9440b291ab21da5b11aa48abc3753a764b82fe25d7c02900d8b7811ca0d71f82911df27af6fddcbe2c497e343239f4c4cdec55c5035475e2efff07303c1cd9b1f3b40e558a2c1f4abb976e807c2f5052c8dc5ef6599644faa2154f75b72cfd104c58fd32de6bbf99c189956a242e5c2cb1ca0d4f3f264b254981d640b485063983f0a483f355a994d3fa2c2e0c8a4b25d60265616d1a34d694e9e373454ce126856829996bb41c1ab170c6e6025d733f6daad046a2f133a29870e25db68d268b3caea7307fc94c1e47fdd5d09dbae26d4b76fc7
#TRUST-RSA-SHA256 3ea08ee0985532df9c4de2538fe9c4db748187e5df02df7290d61851ab77ddf4048ddf4e9faf5e1aa63c7c06535b1e7ad9586fd6e9a8505b65d2131c856a2a424113131626511763822721ad4ba83a54cac754785546460ca807e8ae06f8d67626abbb551ccefe798c25a43c26882c6fefaa32b8e55b277e81d29a82268ef09c38daf826cc2a85771cd1380b254a16e7954cf3360cf03695b186f29445bcb5eec3e27bbb4c214865ceae0959b3c89557bb809ff3692a81e615c80797ef17e136b308f236c51d6b2e075ed84af36236424bec726f81030216f6a01981822c08590bc6e8983fbb607f75df3b6ccc81ebeefa50f7de38ee29b952eacd077c2250a1129c771dac0b52ebc2d6846da451733027118ffd4f9a99bb4542ea59e8b3e2c5dac57020801823a931f4a03494e01671bf3fb5bce38cab04c5fd373fbb5d96c8de882d839bba2176853f88400e6bef4fd2d6d95603e0079c78c42f0087e9ea70cc535383988e6bd2a931de31a373a26d9b17e65e568b73af1a0887072d0a6c43ae9f7ef92351f01ddf676dfb33d2db761789633c5868b8244c609e94c40ec1dd96c90b19b080de2041c715a7512f403a7f930de9605bdaf2596ab68a35df6094458fed789d97cf0c97302c2d1966b7ce45972a9848b34e6175d9dd8bd73e50874a7b4cc6260a8fc28af69132679ee61b33a317f8e68a3a8e5162b66339764be2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(152684);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_name(english:"SSH Cisco Wireless LAN Controller (WLC) Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is a Cisco Wireless LAN Controller (WLC).");
  script_set_attribute(attribute:"description", value:
"The remote device is a Cisco Wireless LAN Controller (WLC).");
  # https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2102cd2");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCve45024");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_rate_limiting.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_func.inc');
include('ssh_lib.inc');

var app_name = 'Cisco WLC';
if(islocalhost()) info_t = INFO_LOCAL;
else info_t = INFO_SSH;

enable_ssh_wrappers();

# check if none_auth Cisco WLC via ssh banner
var port22 = kb_ssh_transport();
if ( port22 && get_port_state(port22) )
{
 var _ssh_socket = open_sock_tcp(port22);
 if ( _ssh_socket )
 {
   ssh_banner = ssh_exchange_identification();
   ssh_close_connection();

   if ('-CISCO_WLC' >!< ssh_banner) audit(AUDIT_NOT_DETECT, app_name);
   set_kb_item(name:'Host/' + port22 + '/Cisco_WLC_banner/', value:ssh_banner);
   set_kb_item(name:'Host/Cisco/WLC/none_auth', value:TRUE);
 }
}

# try loggin in using the none_auth via sshlib::try_ssh_kb_settings()
var session = new('sshlib::session');
var channel = TRUE;
var login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:TRUE, rate_limit:FALSE, new_channel:channel, force_none_auth:TRUE);

if(!login_res)
{
  # remove the failure so that plugins down the chain can verify after service detection
  rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
  session.dbg_log(message:'Login via sshlib::try_ssh_kb_settings_login has failed.');
  audit(AUDIT_FN_FAIL, 'sshlib::try_ssh_kb_settings_login');
}

# Enable local checks only after login was successful
sshlib::enable_local_checks();

# show run-config
channel.clear_data_buf();
channel.window_send_data(data:'show run-config\n\n\n\n\x1a');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show run-config", value:substr(channel.data_buf, 15));

# confirm if this is a wlc buy looking for Cisco Controller in the product name
if (!preg(pattern:"Product Name\.+ Cisco Controller[\r\n]", string:channel.data_buf, multiline:TRUE))
{
  channel.close();
  session.close_connection();
  audit(AUDIT_NOT_DETECT, app_name);
}

# config paging disable
channel.clear_data_buf();
channel.window_send_data(data:'config paging disable\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);

# show sysinfo
channel.clear_data_buf();
channel.window_send_data(data:'show sysinfo\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show sysinfo", value:substr(channel.data_buf, 12));

# show inventory
channel.clear_data_buf();
channel.window_send_data(data:'show inventory\n');
session.sshrecv_until(
  end_states : make_list('SOC_CLOSED'),
  channel: channel,
  check_callback : @cisco_wlc_cmd_prompt_cb,
  cmd_timeout: 40
);
if (channel.data_buf) set_kb_item(name:"Host/Cisco/show inventory", value:substr(channel.data_buf, 14));

channel.close();
session.close_connection();

set_kb_item(name:'Host/OS/Cisco_WLC', value:TRUE);
var report = 'The remote host has has been identified as a Cisco Wireless LAN Controller (WLC) device that does NOT\n' +
             'directly put the user into the device user CLI when login in through an SSH terminal session but ends\n' +
             'up at a username prompt and requires re-entry of credentials (Cisco Bug: CSCve45024).\n\n' +
             'Nessus has managed to run commands in support of OS fingerprinting';

security_report_v4(port:port22, severity:SECURITY_NOTE, extra:report);

##
# Callback function for Cisco Wireless LAN Controller (WLC) devices. Check if we are at a Cisco Controller prompt. 
# Used in sshlib::try_ssh_kb_settings_login(). By the time this runs we already know the device is a Cisco WLC. This 
# is run when sending commands to the device, to determine when the command has completed. 
# 
# @param session  An sshlib::session object
# @param channel  An sshlib::channel object
# @return Returns TRUE if the channel data buffer ends with a Cisco Controller prompt, else returns FALSE.
# @category SSH 
##
function cisco_wlc_cmd_prompt_cb(session, channel)
{
  return (channel.data_buf =~ "\n\(Cisco Controller\) >$");
}
