#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56750);
  script_version("1.9");
  script_cvs_date("Date: 2018/07/16 14:09:14");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_bugtraq_id(50589, 50593, 50595);

  script_name(english:"Firefox 3.6.x < 3.6.24 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.6.x is earlier than 3.6.24 and is
potentially affected by the following vulnerabilities:

  - There is an error within the JSSubScriptLoader that
    incorrectly unwraps 'XPCNativeWrappers'. By tricking
    a user into installing a malicious plug-in, an attacker
    could exploit this issue to execute arbitrary code.
    (CVE-2011-3647)

  - Certain invalid sequences are not handled properly in
    'Shift-JIS' encoding and can allow cross-site scripting
    attacks. (CVE-2011-3648)

  - Profiling JavaScript files with many functions can cause
    the application to crash. It may be possible to trigger
    this behavior even when the debugging APIs are not being
    used. (CVE-2011-3650)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-49/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.24', min:'3.6', severity:SECURITY_HOLE);