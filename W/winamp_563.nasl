#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59756);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-3889", "CVE-2012-3890", "CVE-2012-4045");
  script_bugtraq_id(54131);
  script_xref(name:"SECUNIA", value:"46624");

  script_name(english:"Winamp < 5.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows. 

The version of Winamp installed on the remote host is earlier than
5.63 and is, therefore, reportedly affected by the following
vulnerabilities :

  - A memory corruption error exists in 'in_mod.dll'
    related to input validation when handling 'Impulse
    Tracker' (IT) files.

  - Heap-based buffer overflows exist related to
    'bmp.w5s' when handling 'BI_RGB' and 'UYVY' data in AVI
    files. Processing decompressed TechSmith Screen Capture
    Codec (TSCC) data in AVI files can also trigger a heap-
    based buffer overflow.

Successful exploitation can allow arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?t=345684");
  script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/help/Version_History");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp 5.63 (5.6.3.3234) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Winamp/Version");
fixed_version = "5.6.3.3234";

path = get_kb_item("SMB/Winamp/Path");
if (isnull(path)) path = 'n/a';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Winamp", version, path);
