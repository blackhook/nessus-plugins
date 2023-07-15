#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88754);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1949");
  script_xref(name:"MFSA", value:"2016-13");

  script_name(english:"Firefox < 44.0.2 Service Workers Security Bypass");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 44.0.2. It is, therefore, affected by a security bypass
vulnerability due to improper restriction of interaction between
service workers and plugins. An unauthenticated, remote attacker can
exploit this, via a crafted web site that triggers spoofed responses
to requests that use NPAPI, to bypass the same-origin policy.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 44.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'44.0.2', severity:SECURITY_WARNING);
