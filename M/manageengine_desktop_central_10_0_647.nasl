##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148038);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/10");

  script_cve_id("CVE-2020-28050");
  script_xref(name:"IAVA", value:"2021-A-0145-S");

  script_name(english:"ManageEngine Desktop Central < 10.0.647 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Windows host contains a Java-based web application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the Windows host is prior to version 10 build 10.0.647. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - Zoho ManageEngine Desktop Central before build 10.0.647 allows a single authentication secret from
    multiple agents to communicate with the server. (CVE-2020-28050)

  - A stored cross-site scripting vulnerability in the Inventory section due to improper validation of
    user-supplied input.

  - Improper authorization handling of agent data posted to the server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/desktop-central/fixing-multiple-vulnerabilities.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ac48c88");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 10 build 10.0.647 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_installed.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'ManageEngine Desktop Central', win_local:TRUE);

constraints = [{'fixed_version':'10.0.647', 'fixed_display':'10.0.647 (10 build 100647)'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
