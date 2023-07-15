#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105039);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-7843", "CVE-2017-7844");
  script_bugtraq_id(102039);

  script_name(english:"Mozilla Firefox < 57.0.1 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 57.0.1. It is, therefore, affected by multiple
vulnerabilities.

Note: CVE-2017-7844 only affects version 57. Earlier releases are
not affected.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-27/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 57.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'57.0.1', severity:SECURITY_WARNING);
