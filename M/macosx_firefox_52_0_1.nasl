#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99123);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-5428");
  script_bugtraq_id(96959);
  script_xref(name:"MFSA", value:"2017-08");

  script_name(english:"Mozilla Firefox < 52.0.1 CreateImageBitmap RCE (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote macOS or Mac
OS X host is prior to 52.0.1. It is, therefore, affected by an integer
overflow condition in the nsGlobalWindow::CreateImageBitmap() function
within file dom/base/nsGlobalWindow.cpp due to improper validation of
certain input. An unauthenticated, remote attacker can exploit this to
corrupt memory, possibly resulting in the execution of arbitrary code.

Note that this function runs in the content sandbox, requiring a
second vulnerability to compromise a user's computer.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-08/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 52.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (!isnull(is_esr)) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', fix:'52.0.1', severity:SECURITY_HOLE);
