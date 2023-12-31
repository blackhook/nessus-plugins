#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85274);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2015-4495");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Firefox ESR < 38.1.1 PDF Reader Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by an
arbitrary file access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 38.1.1. It is, therefore, affected by a vulnerability in the
same origin policy in which an attacker can inject script code into a
non-privileged part of browser's built-in PDF reader, resulting in
gaining access to sensitive local files.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-78/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1179262");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR 38.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4495");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'38.1.1', severity:SECURITY_WARNING);