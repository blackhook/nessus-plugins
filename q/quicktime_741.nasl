#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30204);
  script_version("1.13");

  script_cve_id("CVE-2008-0234");
  script_bugtraq_id(27225);

  script_name(english:"QuickTime < 7.4.1 RTSP Response Long Reason-Phrase Arbitrary Remote Code Execution (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of QuickTime installed on the remote Windows host is older
than 7.4.1.  Such versions contain a heap-based buffer overflow in the
application's handling of HTTP responses when RTSP tunneling is
enabled.  If an attacker can trick a user into visiting a specially crafted
webpage, arbitrary code could be executed on the remote host subject to the
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486091" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307407" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Feb/msg00001.html" );
 script_set_attribute(attribute:"solution", value:
"Either use QuickTime's Software Update preference to upgrade to the
latest version or manually upgrade to QuickTime 7.4.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/07");
 script_cvs_date("Date: 2018/07/25 18:58:06");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}

#

include("global_settings.inc");

ver = get_kb_item("SMB/QuickTime/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

if (
  iver[0] < 7 || 
  (
    iver[0] == 7 && 
    (
      iver[1] < 4 ||
      (iver[1] == 4 && iver[2] < 1)
    )
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Version ", ver, " of QuickTime is currently installed\n",
      "on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
