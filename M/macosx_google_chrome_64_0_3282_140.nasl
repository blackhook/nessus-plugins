#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106683);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:14");


  script_name(english:"Google Chrome < 64.0.3282.140 V8 Factory::NewFunction() RCE (macOS)");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host is affected by
a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is prior
to 64.0.3282.140. It is, therefore, affected by a flaw in the
V8 JavaScript engine as noted in Chrome stable channel update
release notes for February 1st, 2018. Please refer to the
release notes for additional information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?205f733f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 64.0.3282.140 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'64.0.3282.140', severity:SECURITY_WARNING);
