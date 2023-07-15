#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14245);
 script_version("1.18");

 script_cve_id("CVE-2004-0537");
 script_bugtraq_id(10452);

 script_name(english:"Opera < 7.51 favicon.ico Address Bar Spoofing");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is vulnerable to 
address bar spoofing attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Opera is vulnerable to a security weakness that may
permit malicious web pages to spoof address bar information.  It is
reported that the 'favicon' feature can be used to spoof the domain of
a malicious web page.  An attacker can create an icon that includes
the text of the desired site and is similar to the way Opera displays
information in the address bar.  The attacker can then obfuscate the
real address with spaces. 

This issue can be used to spoof information in the address bar, page
bar and page/window cycler." );
 script_set_attribute(attribute:"see_also", value:"http://www.greymagic.com/security/advisories/gm007-op/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/windows/changelogs/751/" );
 script_set_attribute(attribute:"solution", value:
"Install to Opera 7.51 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/03");
 script_cvs_date("Date: 2018/07/16 14:09:15");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 51)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
