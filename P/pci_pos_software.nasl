#TRUSTED 3f4444eb560af017d117ab1a093ced10f9df67f2c1017df88a533e741ab371eade3fd0b4a6aee9a86a6348366fb8763a86676565178dbf40344179ed88953306ba20299367b29447ab0bbfc6783a37a49b79bb09eb84d65369f956dcc6daf15c139ecc93ad738c306185e61e3b442890ea279ec1ec39873d1ff39fca6a128012d137494e1662f7135d14f3d7a0faa23d1cca1e50881c2d1653f11c04086b727f48d3d7d372f87644323e41eefb0551cd234683f26306c2cce87d543f729c7c64bb8d2e87716ab5ff8171ef40f2ee9650ac26f49378fcaba7e0ffbe222882a482dc00056ac22b13e9b269eaaa5fdfb3d2a02f674c489bd9ec16465fb6ee5165b2cf1f6b4fd72b64188a757b22c8ce8cd76f198dec3e10e2c74c0a2a87c4d0d86e4048123fc2413673dec59f0a1952f578b7e17bb6e8d8f3174571425fb2645344d317a83529887c468a8acbfb4bd04d402306f4644c047bae50fec57695adde65118a4c6cf86c7bcb9d011d0266ee5ee8aea8873ef44b6731b5109edf35fd9e8040b70ae05985bb8e60500e440742ac796237642261fa8f59bcc9dab730cf05038a625e7875065f207467228356cefd63898e1a246e7cd431b0ddb37d180a7c7fee2139d1139d047215fbc31d24bb06c0e97a4af5cf951b1b1bfa83f7e60fc378dc49b52a0c2c5e37ddceed1590a3a9804fb38b244141d3a7d9fb7c10b4509caf
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(108410);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_name(english:"PCI DSS Compliance : Point-of-Sale (POS) Software");
  script_summary(english:"Check for Point-of-Sale software for PCI DSS compliance.");

  script_set_attribute(attribute:"synopsis", value:
"Point-of-Sale software has been detected running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Due to increased risk to the cardholder data environment when a
point-of-sale system is visible on the Internet, 1) confirm that this
system needs to be visible on the Internet, that the system is
implemented securely, and that original default passwords have been
changed to complex passwords, or 2) confirm that the system has been
reconfigured and is no longer visible to the Internet. Consult your
ASV if you have questions about this Special Note.");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_end_attributes();

  script_category(ACT_END);

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Policy Compliance");

  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Settings/PCI_DSS_local_checks");
  exit(0);
}

include("compat_shared.inc");
include("install_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Settings/PCI_DSS_local_checks"))
  exit(1, "This plugin only runs for PCI External scans.");
##
# Returns any URLS found for the specified POS product
#
# @param  string  app  POS software
# @param  int     port 
#
# @return list    list of URLs from get_installs()
##
function get_urls(app, port)
{
  local_var installs, install, url, urls;

  if (isnull(app) || isnull(port)) return NULL;
  if (!get_kb_item('www/' + port + '/webapp_installed')) return NULL;

  installs = get_installs(app_name:app, port:port);
  if (installs[0] != IF_OK) return NULL;

  urls = make_list();
  foreach install (installs[1])
  {
    url = build_url2(qs:install['path'], port:port);
    if (!empty_or_null(url))
      urls = make_list(urls, url);
  }
  return urls;
}


port_kbs = get_kb_list("PCI/POS/*");
if (empty_or_null(port_kbs)) audit(AUDIT_HOST_NONE, "Point-of-Sale (POS) software");

report = NULL;

foreach port_kb (keys(port_kbs))
{
  port = int(port_kb - "PCI/POS/");
  app = port_kbs[port_kb];

  report += '\n' + app + ' is running on the remote host on port ' + port;  

  urls = get_urls(app:app, port:port);
  if (!empty_or_null(urls))
  {
    locations = "URL";
    if (max_index(urls) > 1) locations += "s";

    report += ' at the following ' + locations + ' :\n  ' + join(urls, sep:'\n  ');
  }
  else
    report += '.\n';
}

if (empty_or_null(report)) audit(AUDIT_HOST_NONE, "Point-of-Sale (POS) software"); # This shouldn't happen

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
