#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59197);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_xref(name:"IAVA", value:"0001-A-0509");

  script_name(english:"Adobe Flash Player Unsupported Version Detection (Mac OS X)");
  script_summary(english:"Checks if any Flash player versions are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Flash
Player.");
  script_set_attribute(attribute:"description", value:
"There is at least one unsupported version of Adobe Flash Player
installed on the remote Mac OS X host.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  # http://helpx.adobe.com/flash-player/kb/flash-player-9-support-discontinued.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f12ecc3");
  # https://web.archive.org/web/20171118195009/http://blogs.adobe.com/flashplayer/2013/05/extended-support-release-updated-to-flash-player-11-7.html#sthash.XCWNrykD.dpbs
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?04242608");
  # https://web.archive.org/web/20170504200148/https://blogs.adobe.com/flashplayer/2014/03/upcoming-changes-to-flash-players-extended-support-release.html
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?ae1d5118");
  # https://web.archive.org/web/20170508214430/https://blogs.adobe.com/flashplayer/2015/05/upcoming-changes-to-flash-players-extended-support-release-2.html#sthash.7Sjh1NUX.dpbs
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?e42f403a");
  script_set_attribute(attribute:"solution", value:
"Remove the unsupported software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("macosx_flash_player_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Flash_Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Flash_Player";

version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

### The following versions/dates are no longer in use.  Perserved for posterity
eos_dates = make_array(
  # Version regex     , EOL date if available
  '^17\\.'            , '2015-08-11',  # EOL with 18.x release
  '^16\\.'            , '2015-03-12',  # EOL with 17.x release
  '^15\\.'            , '',
  '^14\\.'            , '2014-09-09',  # EOL with 15.x release
  '^13\\.'            , '2015-08-11',  # EOL with 18.x release
  '^12\\.'            , '',
  '^11\\.7($|\\.)'    , '2014-05-13',
  '^11\\.[0-6]($|\\.)', '',
  '^([0-9]|10)\\.'    , ''
);


supported_versions = 'None';

info = "";

if (version)
{
  register_unsupported_product(product_name:'Adobe Flash Player',
                               version:version, cpe_base:"adobe:flash_player");

  info =
         '\n  Path               : ' + path +
         '\n  Installed version  : ' + version +
         '\n  End of life date   : 2020-12-31' +
         '\n';
}

if (info)
{
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:info);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe Flash Player", version, path);
