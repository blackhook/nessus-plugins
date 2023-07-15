#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117667);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-12385");

  script_name(english:"Mozilla Firefox < 62.0.2 Vulnerability (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS host is
prior to 62.0.2. It is, therefore, affected by a vulnerability as
noted in Mozilla Firefox stable channel update release notes for
2018/09/21. Please refer to the release notes for additional
information. Note that Nessus has not attempted to exploit these
issues but has instead relied only on the application's self-reported
version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1490585
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7fa8df5");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-22/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a35eec72");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 62.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'62.0.2', severity:SECURITY_WARNING);
