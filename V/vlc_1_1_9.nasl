#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53405);
  script_version("1.6");
  script_cvs_date("Date: 2018/08/06 14:03:16");

  script_cve_id("CVE-2011-1684");
  script_bugtraq_id(47293);
  script_xref(name:"Secunia", value:"44022");

  script_name(english:"VLC Media Player < 1.1.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a media player that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VLC media player installed on the remote host is
earlier than 1.1.9.  Such versions are affected by multiple
vulnerabilities:

  - A heap based buffer overflow exists in the function 
    'MP4_ReadBox_skcr' in 'modules/demux/mp4/libmp4.c'.
    This issue can be triggered when parsing of a
    malicious MP4 file and lead to application crashes and 
    possibly arbitrary code execution.

  - An unspecified error exists in the third-party 
    libmodplug component included with VLC."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/vlc/releases/1.1.9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.videolan.org/security/sa1103.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to VLC Media Player version 1.1.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/VLC/Version");

# nb: 'version' may look like '0.9.8a'!
# the advisory says versions 1.0.0 - 1.1.8 are affected
if (
  version =~ "^1\.0\." ||
  version =~ "^1\.1\.[0-8]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/VLC/File");
    if (isnull(path)) path = "n/a";
    else path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.1.9\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
else exit(0, "The host is not affected since VLC "+version+" is installed.");
