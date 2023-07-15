#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117918);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-12386", "CVE-2018-12387");
  script_bugtraq_id(105460);
  script_xref(name:"MFSA", value:"2018-24");

  script_name(english:"Mozilla Firefox < 62.0.3 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS host
is prior to 62.0.3. It is, therefore, affected by multiple
vulnerabilities as noted in Mozilla Firefox stable channel update
release notes for 2018/10/02. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1493900
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c59dd1b");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=1493903
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5d12f1e");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-24/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b443a0e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 62.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

mozilla_check_version(product:'firefox', version:version, path:path, esr:FALSE, fix:'62.0.3', severity:SECURITY_WARNING);
