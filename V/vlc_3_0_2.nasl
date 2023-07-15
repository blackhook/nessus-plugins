#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111518);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-11516");
  script_bugtraq_id(104293);

  script_name(english:"VLC 3.0.x < 3.0.2 Heap Use-After-Free / Remote Code Execution Vulnerability");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by a
heap use-after-free remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is earlier
than 3.0.2.  It is, therefore, affected by a heap use-after-free
vulnerability which could result in a remote code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/VLC/Version");

path = get_kb_item_or_exit("SMB/VLC/File");
path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (version =~ "^3\.0\.[0-1]($|[^0-9])")
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.0.2\n' + 
      '\n'
  );
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VLC", version, path);
