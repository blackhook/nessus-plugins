#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82997);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-2706");
  script_bugtraq_id(74247);

  script_name(english:"Firefox < 37.0.2 Failed Plugin Memory Corruption (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Mac OS X host is prior
to 37.0.2. It is, therefore, affected by a use-after-free error,
related to the AsyncPaintWaitEvent() method, due to a race condition
caused when plugin initialization fails. A remote attacker, using a
crafted web page, can exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-45/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 37.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (get_kb_item(kb_base + '/is_esr')) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'37.0.2', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
