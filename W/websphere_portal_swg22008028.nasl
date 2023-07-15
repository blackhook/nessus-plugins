#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102996);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-1189");

  script_name(english:"IBM WebSphere Portal XSS (swg22008028)");
  script_summary(english:"Checks for the install patches.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Portal installed on the remote host is version
6.1.0.x prior to 6.1.0.6 CF27, 6.1.5.x prior to 6.1.5.3 CF27,
7.0.0.x prior to 7.0.0.2 CF30, 8.0.0.x prior to 8.0.0.1 CF22, and
is therefore affected by a cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22008028");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fixes per the vendor advisory.

  - For 6.1.0.x, upgrade to version 6.1.0.6 CF27 and apply
    interim fix PI78908.

  - For 6.1.5.x, upgrade to version 6.1.5.3 CF27 and apply
    interim fix PI78908.

  - For 7.0.0.x, upgrade to version 7.0.0.2 CF30 and apply
    interim fix PI78908.

  - For 8.0.0.x, upgrade to version 8.0.0.1 CF22 and apply
    interim fix PI78908.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1189");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  checks:make_array(
    "8.0.0.0, 8.0.0.1, CF22", make_list("PI78908"),
    "7.0.0.0, 7.0.0.2, CF30", make_list('PI78908'),
    "6.1.5.0, 6.1.5.3, CF27", make_list('PI78908'),
    "6.1.0.0, 6.1.0.6, CF27", make_list('PI78908')
 ),
  severity:SECURITY_WARNING,
  xss: TRUE
);
