#TRUSTED 5dfddf7e9b583d57749c498ab43b075a4ad465f9cac85b3f9e4d5622e724cc2718b858dc4ea4b29c02d8a192402409c1741bf618e66ee04ee16c726561cc5953c7e8458f51232533468bacff6d494285d3e9c7554204b7297b65b1478103c4c052fb4f8c1a3e2e287be87bef91d3bdee094d9de52a96e370fff3c1a7b6694ab4a828b13649872698385acc0025df1d6bbc54222e2844a330f2eb1b85131453745cf84acbf9c87481264a9d2c60bca98ab46865e3e55e90ed760dbe09214d56c4d57d1796006e990adda728247294d21d939ef805ef1f56e63a2bf66d1eae61a654215d4aa0956ff0e8a094399c2f3427ff43e8546bd097428919a0cea7d3b844f85d92468a579c2e0782dadc04454ec7e07920b5ea3b03c3383a5ed2842a085288dd9c8c5eb173b8b296d5379705300db60e693df2cd4f00897a5a1526ff0349bb1d8d91aa762b962ebfbec7ca4b14eb8d7748bc14f792615d3175998351b304c86a9e111a9b6fd1e41a444a698d356b3316122acbf62859c65a7abe62a4717a54ea8aebd106209e8b725c9c95d9b8a7cb16bf4c30fd50846de0ef1aea95180aa2949cef77d19db07d4310b788a92f329d1aba6f30653c82c04e72690e3604b287dd93e8c5cd679223a68e275d734744f2c3dbe806cfacdb2504c10806cfe437a19b29411216defde2347213389c8294b1d8c8c2effc39fb963c2f46dadd0a3f
#TRUST-RSA-SHA256 2427f3b66d0bcc9d7e8ba91b0d7f8d039726039e69c04f8ad957c95b8f3f53d046623c4859eadc89132e7dc8ca90758e66d4bcc6eb91b009ca99d0e7882b7d73890a2e91914b11547e32aca4b53740f68eebdf6a2590e00feffcc8afaeabde03fde974293cfa730991224581f2abbdc4b061f1e9afb4dda6942d2b0361ba66f2a1e603b5e52967b5ff1130d4ff6c2101758864e8b6d25d459dd5209622ba131652c89fbd61eaca14ce4ca1514193425df725490eade0819d959dd067695a22504465bba73231731a9b3265733a75c9fce77e9bfe984b7a256b3cd62b9d7a8aceee1f79294274689c931990285b5d5e4b1071a85b5005313c6013cf22f9592fcf67be571107dcbbc4fc7cfd12bc7aeb344a3bfce4fdf596187126e83c4ee96a84a5953005e8d69539a12c4b111a692effe58252de46689ac701e3e257cebcc04830b2de2b2ac5525bebdf4cff642ffc7c16d2684cc7ad9ec1e993803669ff102a02a67b003c2bd6fc68d7d168843823331c8f7f9036ca3fc42d51b6e1334b0fc67e4f632ab68fb04a702793d49fe54eec21bfa74e3ecef5cca3fd4f0c845520acadff33825c33a3795747370ffa853d2d921d79be1d327bd8c110e38bdb798d83ab9dbfcda9c7a8328410a4ec9284d345d63cddde9713d0f715958b0892161fac8c7a76eef14b8fc86a7f3962bb276149a38b5d891a15b71bc0fd0b0c15303fe7
##
# (C) Tenable Network Security, Inc.
##
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include("compat.inc");

if (description) {
  script_id(13858);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/04");

  script_name(english:"osTicket Detection");

  script_set_attribute(attribute:"synopsis", value:
"osTicket was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"osTicket was detected on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://osticket.com/");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:osticket:osticket");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('osticket_version_mapping.inc');
include('install_func.inc');

var port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0,'The remote web server does not support PHP.');

var app = 'osTicket';
var cpe = 'cpe:/a:osticket:osticket';
var product = 'osTicket';
var vendor = 'Enhancesoft';

var pattern_paths = ['/css/osticket.css', '/assets/default/css/theme.css', '/assets/default/css/print.css', '/scp/css/typeahead.css'];
var pattern_old_ver = "alt=.osTicket STS v([\d.]+)";
var version;

var url, res, match, matches;
var is_osticket = false;
foreach var dir (cgi_dirs())
{
  version = NULL;
  url = strcat(dir, '/open.php');
  res = http_send_recv3(port:port, method:'GET', item:url, exit_on_fail:true);
  if (preg(pattern:'content="osTicket, Customer support system, support ticket system"', string:res[2], multiline:true))
  {
    version = UNKNOWN_VER;
    foreach var path(pattern_paths)
    {
      match = pregmatch(pattern:strcat('href="', path, '\\?([\\da-f]{7})"'), string:res[2]);
      if (match)
      {
        if (os_ticket_version_map[match[1]])
        {
          version = os_ticket_version_map[match[1]];
          break;
        }
      }
    }
  }
  # Support for older versions
  else if (preg(pattern:'alt="osTicket', string:res[2], multiline:true))
  {
    version = UNKNOWN_VER;
    match = pregmatch(pattern:pattern_old_ver, string:res[2]);
    if (match)
    {
      version = match[1];
      # 1.2.5, 1.2.7, and 1.3.x all report 1.2; try to distinguish among them.
      if (version == '1.2')
      {
        # 1.3.0 and 1.3.1.
        if ('Copyright &copy; 2003-2004 osTicket.com' >< res[2])
        {
          # nb: 1.3.1 doesn't allow calling 'include/admin_login.php' directly.
          url = strcat(dir, '/include/admin_login.php');
          res = http_send_recv3(port:port, method:'GET', item:url, exit_on_fail:true);
          if ('<td>Please login:</td>' >< res[2])
          {
            version = '1.3.0';
          }
          else if ('Invalid path' >< res[2])
          {
            version = '1.3.1';
          }
          else
          {
            version = UNKNOWN_VER;
            dbg::detailed_log(lvl:1, msg:"Can't determine version (1.3.x series)");
          }
        }
        # 1.2.5 and 1.2.7
        else
        {
          # nb: 1.2.5 has an attachments dir whereas 1.2.7 has attachments.php
          url = strcat(dir, '/attachments.php');
          res = http_send_recv3(port:port, method:'GET', item:url, exit_on_fail:true);
          if ('You do not have access to attachments' >< res[2])
          {
            version = '1.2.7';
          }
          else if ('404 Not Found' >< res[2])
          {
            version = '1.2.5';
          }
          else
          {
            version = UNKNOWN_VER;
            dbg::detailed_log(lvl:1, msg:"Can't determine version (1.2.x series)");
          }
        }
      }
    }
  }

  if (version)
  {
    if (dir == '') dir = '/';
    register_install(app_name:app, product:product, vendor:vendor, path:dir, port:port, version:version, cpe:cpe, webapp:TRUE);

    # Keeping these KBs to maintain compatibility with downstream plugins from older versions
    set_kb_item(name:strcat("www/", port, "/osticket"), value:strcat(version, ' under ', dir));
    set_kb_item(name: "www/osticket", value: TRUE);

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}

get_install_count(app_name:app, exit_if_zero:true);
report_installs(app_name:app, port:port);
