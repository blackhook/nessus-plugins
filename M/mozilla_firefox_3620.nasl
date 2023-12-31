#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55901);
  script_version("1.15");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2011-0084",
    "CVE-2011-2378",
    "CVE-2011-2980",
    "CVE-2011-2981",
    "CVE-2011-2982",
    "CVE-2011-2983",
    "CVE-2011-2984"
  );
  script_bugtraq_id(
    49213,
    49214,
    49216,
    49217,
    49218,
    49219,
    49223
  );

  script_name(english:"Firefox 3.6 < 3.6.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6 is earlier than 3.6.20.  As
such, it is potentially affected by the following security issues :

  - A dangling pointer vulnerability exists in an SVG text
    manipulation routine. (CVE-2011-0084)

  - A DOM accounting error exists in the 'appendChild' 
    JavaScript function that can allow an invalid pointer
    to be dereferenced. (CVE-2011-2378)

  - An error exists in 'ThinkPadSensor::Startup' that can
    allow malicious DLLs to be loaded. (CVE-2011-2980)

  - An error exists in the event management code that can
    allow JavaScript to execute in the context of a 
    different website and possibly in the
    chrome-privileged context. (CVE-2011-2981)

  - Various unspecified memory safety issues exist. 
    (CVE-2011-2982)

  - A cross-domain information disclosure vulnerability
    exists if the configuration option 'RegExp.input' is
    set. (CVE-2011-2983)

  - A privilege escalation vulnerability exists if web
    content is registered to handle 'drop' events and a 
    browser tab is dropped in that element's area. This 
    can allow the web content to execute with browser
    chrome privileges. (CVE-2011-2984)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-270/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-271/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.20', min:'3.6', severity:SECURITY_HOLE);