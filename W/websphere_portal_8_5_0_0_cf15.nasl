#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106395);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1361");
  script_bugtraq_id(102501);

  script_name(english:"IBM WebSphere Portal 8.5.0.x < 8.5.0.0 CF15 Unspecified XSS (PI92039)");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote Windows
host is 8.5.0.x prior to 8.5.0.0 CF15. It is, therefore, affected by
a cross-site scripting (XSS) vulnerability which can potentially
lead to the disclosure of credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22012409");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 8.5.0.0 Cumulative Fix 15 (CF15) and
apply Interim Fix PI92039 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1361");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.5.0.0, 8.5.0.0, CF15"),
  fix:"PI92039",
  severity:SECURITY_WARNING,
  xss:TRUE
);
