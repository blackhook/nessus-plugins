#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if (description)
{
  script_id(29699);
  script_version("1.19");
  script_cve_id("CVE-2007-4706", "CVE-2007-4707", "CVE-2007-6166");
  script_bugtraq_id(26549, 26866, 26868);

  script_name(english:"QuickTime < 7.3.1 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of QuickTime on Mac OS X");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Mac OS X host is older
than 7.3.1.  Such versions contain several vulnerabilities that may
allow an attacker to execute arbitrary code on the remote host if he
can trick the user to open a specially crafted RTSP movie, QTL file,
or Flash media file with QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307176" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2007/Dec/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.3 RTSP Response Header Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/12/13");
 script_cvs_date("Date: 2018/07/14  1:59:35");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
  script_dependencies("macosx_Quicktime652.nasl");
  script_require_keys("MacOSX/QuickTime/Version");
  exit(0);
}

#

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) < 3 ) ||
     (int(version[0]) == 7 && int(version[1]) == 3 && int(version[2]) < 1) ) 
		security_hole(0);
