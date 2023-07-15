#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29742);
  script_version("1.17");

  script_cve_id(
    "CVE-2007-6520", 
    "CVE-2007-6521", 
    "CVE-2007-6522", 
    "CVE-2007-6523", 
    "CVE-2007-6524",
    "CVE-2009-2059",
    "CVE-2009-2063"
  );
  script_bugtraq_id(26721, 26937, 35380, 35412);

  script_name(english:"Opera < 9.25 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues." );
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly is
affected by several issues, including one in which TLS certificates
could be used to execute arbitrary code." );
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/research/publication/pretty-bad-proxy-an-overlooked-adversary-in-browsers-https-deployments/?from=http%3A%2F%2Fresearch.microsoft.com%2Fapps%2Fpubs%2Fdefault.aspx%3Fid%3D79323" );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/search/view/875/" );
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20080516195213/http://www.opera.com/support/search/view/876/" );
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20170714204727/http://www.opera.com:80/docs/changelogs/windows/925/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 9.25 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 189, 200, 287, 310, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/19");
 script_cvs_date("Date: 2018/11/15 20:50:28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version_UI");

  exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) exit(0);

if (version_ui =~ "^([0-8]\.|9\.([01][0-9]|2[0-4])($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Opera version ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
