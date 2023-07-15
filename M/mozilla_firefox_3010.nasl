#
# (C) Tenable Network Security, Inc.


include("compat.inc");

if (description)
{
  script_id(38200);
  script_version("1.18");

  script_cve_id("CVE-2009-1313", "CVE-2009-2061");
  script_bugtraq_id(34743, 35412);
  script_xref(name:"Secunia", value:"34866");

  script_name(english:"Firefox < 3.0.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote host is earlier
than 3.0.10.  Such versions have multiple vulnerabilities :

  - An error in function '@nsTextFrame::ClearTextRun()' could 
    corrupt the memory. Successful exploitation of this issue
    may allow arbitrary code execution on the remote system. 
    Note this reportedly only affects 3.0.9. (MFSA 2009-23)

  - The browser processes a 3xx HTTP CONNECT response before
    a successful SSL handshake, which could allow a man-in-
    the-middle attacker to execute arbitrary web script in the
    context of a HTTPS server. (CVE-2009-2061)");

 script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/research/publication/pretty-bad-proxy-an-overlooked-adversary-in-browsers-https-deployments/?from=http%3A%2F%2Fresearch.microsoft.com%2Fapps%2Fpubs%2Fdefault.aspx%3Fid%3D79323" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-23/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(310, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/28");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/04/27");
 script_cvs_date("Date: 2018/11/15 20:50:27");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.10', severity:SECURITY_HOLE);