#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61432);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-2665");
  script_bugtraq_id(54769);

  script_name(english:"LibreOffice < 3.5.5 Multiple Heap-Based Buffer Overflows");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice prior to 3.5.5 is installed on the remote
Windows host.  It is, therefore, reportedly affected by multiple
heap-based buffer overflow vulnerabilities related to XML manifest
handling :

  - An error exists related to handling the XML tag
    hierarchy.

  - A boundary error exists when handling the duplication
    of certain unspecified XML tags.

  - An error exists in the base64 decoder related to XML
    export actions.");
  script_set_attribute(attribute:"see_also", value:"http://www.pre-cert.de/advisories/PRE-SA-2012-05.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/523851/30/0/threaded");
  # http://blog.documentfoundation.org/2012/07/11/libreoffice-3-5-5-is-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6741ee");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/advisories/CVE-2012-2665/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 3.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("SMB/LibreOffice/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/LibreOffice";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI");

if (
  # nb: first release of LibreOffice was 3.3.0.
  version =~ "^3\.[3-4]\." ||
  (version =~ "^3\.5\." && ver_compare(ver:version, fix:'3.5.5.3', strict:FALSE) == -1)
)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version_ui + 
      '\n  Fixed version     : 3.5.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version_ui, path);
