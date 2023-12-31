#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91916);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-2901");
  script_bugtraq_id(91258);

  script_name(english:"IBM WebSphere Portal 8.5.0 CF08 - CF10 < 8.5.0 CF11 PA_Theme_Creator Application XSRF");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote Windows
host is 8.5.0 CF08 - CF10 prior to 8.5.0.0 CF11. It is, therefore,
affected by a cross-site request forgery (XSRF) vulnerability due to a
failure to require multiple steps, explicit confirmation, or a unique
token when performing certain sensitive actions. An unauthenticated,
remote attacker can exploit this, via a specially crafted link, to
perform unauthorized actions.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21983974");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal version 8.5.0 CF11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2901");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  checks:make_array(
    "8.5.0.0, 8.5.0.0, CF08-CF10", make_list('PI62594')
  ),
  severity:SECURITY_WARNING,
  xsrf:TRUE
);
