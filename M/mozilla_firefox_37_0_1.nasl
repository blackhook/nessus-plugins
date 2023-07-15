#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82583);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0799");
  script_bugtraq_id(73905);

  script_name(english:"Firefox < 37.0.1 HTTP/2 Alt-Svc Header Certificate Verification Bypass");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 37.0.1. It is, therefore, affected by an error related to the
HTTP/2 'Alt-Svc' header and SSL certificate verification, which allows
man-in-the-middle (MitM) attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-44/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 37.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0799");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'37.0.1', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
