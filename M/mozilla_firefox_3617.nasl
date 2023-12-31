#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53594);
  script_version("1.31");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2011-0065",
    "CVE-2011-0066",
    "CVE-2011-0067",
    "CVE-2011-0069",
    "CVE-2011-0070",
    "CVE-2011-0071",
    "CVE-2011-0072",
    "CVE-2011-0073",
    "CVE-2011-0074",
    "CVE-2011-0075",
    "CVE-2011-0077",
    "CVE-2011-0078",
    "CVE-2011-0080",
    "CVE-2011-0081",
    "CVE-2011-1202"
  );
  script_bugtraq_id(
    47641,
    47646,
    47647,
    47648,
    47651,
    47653,
    47654,
    47655,
    47656,
    47657,
    47659,
    47660,
    47662,
    47663,
    47667,
    47668
  );
  script_xref(name:"EDB-ID", value:"17419");
  script_xref(name:"EDB-ID", value:"17520");
  script_xref(name:"EDB-ID", value:"17612");
  script_xref(name:"EDB-ID", value:"17650");
  script_xref(name:"EDB-ID", value:"17672");
  script_xref(name:"EDB-ID", value:"18377");
  script_xref(name:"Secunia", value:"44357");

  script_name(english:"Firefox 3.6 < 3.6.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6 is earlier than 3.6.17.  Such
versions are potentially affected by the following security issues :

  - Multiple use-after-free errors exist in the handling of
    the object attributes 'mChannel', 'mObserverList' and
    'nsTreeRange'. (CVE-2011-0065, CVE-2011-0066, 
    CVE-2011-0073)

  - An error exists in the handling of Java applets that
    can allow sensitive form history data to be accessed.
    (CVE-2011-0067)

  - An error in the resource protocol can allow directory
    traversal. (CVE-2011-0071)

  - Multiple memory safety issues can lead to application 
    crashes and possibly remote code execution.
    (CVE-2011-0069, CVE-2011-0070, CVE-2011-0072, 
    CVE-2011-0074, CVE-2011-0075, CVE-2011-0077, 
    CVE-2011-0078, CVE-2011-0080, CVE-2011-0081)

  - An information disclosure vulnerability exists in the
    'xsltGenerateIdFunction' function in the included
    libxslt library. (CVE-2011-1202)");

  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-157/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-158/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-159/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-13/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-14/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-18/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cbff22e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.17', min:'3.6', severity:SECURITY_HOLE);