#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-01.
# The text itself is copyright (C) Mozilla Foundation.


include('compat.inc');

if (description)
{
  script_id(132708);
  script_version("1.5");
  script_cvs_date("Date: 2020/02/14");

  script_cve_id(
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17020",
    "CVE-2019-17022",
    "CVE-2019-17023",
    "CVE-2019-17024",
    "CVE-2019-17025"
  );
  script_xref(name:"MFSA", value:"2020-01");

  script_name(english:"Mozilla Firefox < 72.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host is prior to 72.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2020-01 advisory, including the following:

- When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer incorrectly
  rewrites a @namespace rule. This could allow for injection into certain types of websites resulting in
  data exfiltration. (CVE-2019-17016)

- Due to a missing case handling object types, a type confusion vulnerability could occur, resulting in a
  crash. We presume that with enough effort that it could be exploited to run arbitrary code.
  (CVE-2019-17017)

- If an XML file is served with a Content Security Policy and the XML file includes an XSL stylesheet, the
  Content Security Policy will not be applied to the contents of the XSL stylesheet. If the XSL sheet e.g.
  includes JavaScript, it would bypass any of the restrictions of the Content Security Policy applied to
  the XML document. (CVE-2019-17020)

- When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer does not escape
  < and > characters. Because the resulting string is pasted directly into the text node of the element
  this does not result in a direct injection into the webpage; however, if a webpage subsequently copies
  the node's innerHTML, assigning it to another innerHTML, this would result in an XSS vulnerability. Two
  WYSIWYG editors were identified with this behavior, more may exist. (CVE-2019-17022)
  
- After a HelloRetryRequest has been sent, the client may negotiate a lower protocol that TLS 1.3,
  resulting in an invalid state transition in the TLS State Machine. If the client gets into this state,
  incoming Application Data records will be ignored. (CVE-2019-17023)

- Mozilla developers Jason Kratzer, Christian Holler, and Bob Clary reported memory safety bugs present in
  Firefox 71 and Firefox ESR 68.3. Some of these bugs showed evidence of memory corruption and we presume
  that with enough effort some of these could have been exploited to run arbitrary code. (CVE-2019-17024)

- Mozilla developers Karl Tomlinson, Jason Kratzer, Tyson Smith, Jon Coppeard, and Christian Holler
  reported memory safety bugs present in Firefox 71. Some of these bugs showed evidence of memory
  corruption and we presume that with enough effort some of these could have been exploited to run
  arbitrary code. (CVE-2019-17025)

Note that Nessus has not tested for this issue but
has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-01/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 72.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include('mozilla_version.inc');

kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

is_esr = get_kb_item(kb_base+'/is_esr');
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'72.0', xss:TRUE, severity:SECURITY_WARNING);

