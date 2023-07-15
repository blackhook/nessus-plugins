#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59606);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-0276", "CVE-2012-0277", "CVE-2012-0282");
  script_bugtraq_id(54030, 54125);
  script_xref(name:"EDB-ID", value:"19181");
  script_xref(name:"EDB-ID", value:"19182");
  script_xref(name:"EDB-ID", value:"19183");
  script_xref(name:"EDB-ID", value:"19335");
  script_xref(name:"EDB-ID", value:"19336");
  script_xref(name:"EDB-ID", value:"19337");
  script_xref(name:"EDB-ID", value:"19338");

  script_name(english:"XnView < 1.99.0 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application with multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of XnView installed on the remote Windows host is earlier
than 1.99.0.  It therefore is reportedly affected by the following
heap-based buffer overflow vulnerabilities :

  - An integer truncation issue exists related to the
    handling of the depth value in 'Sun Raster' (RAS)
    image files.

  - A boundary violation issue exists in 'NCSEcw.dll'
    related to the decompression of 'Enhanced Compressed
    Wavelet' (ECW) image files.

  - A boundary violation issue exists in 'Xfpx.dll'
    related to the handling of 'FlashPix' (FPX) image
    files.

  - Errors exist related to decompressing 'TIFF' images
    that use 'SGI32LogLum' compression.

  - An error exists related to the handling of 'PCT' image
    decompression.

  - An error exists related to the handling of 'GIF' images
    that have certain values for 'ImageLeftPosition'.");
  # https://newsgroup.xnview.com/viewtopic.php?f=35&t=25858&p=103891&hilit=release#p103793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86d25bf7");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=45&Itemid=45
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db1ff78b");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=46&Itemid=46
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8499541f");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=47&Itemid=47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9470d60a");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=48&Itemid=48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01938237");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=49&Itemid=49
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6b263c8");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=50&Itemid=50
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72eb16db");
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=51&Itemid=51
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53b742d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to XnView version 1.99.0 or later as that reportedly resolves
the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0282");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xnview_rgbe_overflow.nasl");
  script_require_keys("SMB/XnView/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/XnView";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
port = get_kb_item("SMB/transport");
path = get_kb_item(kb_base+"/Path");

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 99)
)
{
  if (report_verbosity > 0)
  {
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.99.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
