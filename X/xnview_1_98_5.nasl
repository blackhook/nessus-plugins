#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59174);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/15 20:50:29");

  script_cve_id("CVE-2012-0684", "CVE-2012-0685");
  script_bugtraq_id(51546);
  script_xref(name:"MSVR", value:"MSVR12-001");

  script_name(english:"XnView < 1.98.5 Multiple Integer Overflow Vulnerabilities");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application with multiple integer
overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of XnView installed on the remote Windows host is earlier
than 1.98.5.  As such, it is reportedly affected by multiple integer
overflow vulnerabilities. These vulnerabilities are related to
the processing of PSD (Adobe Photoshop) record types. An attacker
could exploit these vulnerabilities by tricking a victim into opening
a specially crafted file that could allow for arbitrary code to be
executed in the context of the application."
  );
  script_set_attribute(attribute:"see_also", value:"https://newsgroup.xnview.com/viewtopic.php?t=24437");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to XnView version 1.98.5 or later as that reportedly resolves
the issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("xnview_rgbe_overflow.nasl");
  script_require_keys("SMB/XnView/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

kb_base = "SMB/XnView";
get_kb_item_or_exit(kb_base+"/Installed");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
port = get_kb_item("SMB/transport");

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

path = get_kb_item(kb_base+"/Path");
if (isnull(path)) path = "n/a";

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 98 ||
      (ver[1] == 98 && ver[2] < 5)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 1.98.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
