#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65130);
  script_version("1.10");
  script_cvs_date("Date: 2018/07/16 14:09:14");

  script_cve_id("CVE-2013-0787");
  script_bugtraq_id(58391);

  script_name(english:"Firefox ESR 17.x < 17.0.4 nsHTMLEditor Use-After-Free");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by a use-after-free vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR 17.x is earlier than 17.0.4, and
thus, is potentially affected by a use-after-free vulnerability. 

An error exists in the HTML editor (nsHTMLEditor) related to content
script and the calling of the function 'document.execCommand' while
internal editor operations are running.  The previously freed memory can
be dereferenced and could lead to arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526050/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-090/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-29/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.4 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'17.0.4', min:'17.0', severity:SECURITY_HOLE);
