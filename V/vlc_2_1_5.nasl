#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78626);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-0333", "CVE-2014-3466", "CVE-2014-6440");
  script_bugtraq_id(65776, 67741, 72950);
  script_xref(name:"CERT", value:"684412");

  script_name(english:"VLC Media Player < 2.1.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the VLC media player version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior
to 2.1.5. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the png_push_read_chunk() function
    within the file 'pngpread.c' from the included libpng
    library that can allow denial of service attacks.
    (CVE-2014-0333)

  - A buffer overflow error exists in the
    read_server_hello() function within the file
    'lib/gnutls_handshake.c' from the included GnuTLS
    library that can allow arbitrary code execution or
    denial of service. (CVE-2014-3466)

  - A heap-based buffer overflow error exists in the
    transcode module due to improper validation of
    user-supplied input when handling invalid channel
    counts. An attacker can exploit this to execute
    arbitrary code. (CVE-2014-6440)");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.1.5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("installed_sw/VLC media player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "VLC media player";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fix = "2.1.5";
if (
  version =~ "^[01]\." ||
  version =~ "^2\.0($|[^0-9])" ||
  version =~ "^2\.1\.[0-4]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + 
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
