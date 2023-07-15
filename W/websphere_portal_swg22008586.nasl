#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103568);
  script_version("1.3");
  script_cvs_date("Date: 2018/08/06 14:03:14");

  script_cve_id("CVE-2017-1577");

  script_name(english:"IBM WebSphere Portal (swg22008586)");
  script_summary(english:"Checks for the install patches.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is 
vulnerable to a path traversal vulnerability that could allow a 
remote attacker to traverse directories on the system. An attacker 
could send a specially-crafted URL request containing 'dot dot' 
sequences (/../) to view arbitrary files on the system.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22008586");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fixes per the vendor advisory.

  - For 7.0.0.x, upgrade to version 7.0.0.2 CF30 and apply
    interim fix PI87495.

  - For 8.0.0.x, upgrade to version 8.0.0.1 CF30 and apply
    interim fix PI87495.

  - For 8.5.x, upgrade to CF15, or upgrade to either CF13 
    or CF14 and apply interim fix PI87495.

  - For 9.0.x, upgrade to CF15, or upgrade to either CF13 
    or CF14 and apply interim fix PI87495.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/09/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  checks:make_array(
    "9.0.0.0, 9.0.0.0, CF00-CF14", make_list("PI87495"),
    "8.5.0.0, 8.5.0.0, CF00-CF14", make_list("PI87495"),
    "8.0.0.0, 8.0.0.1, CF22", make_list("PI87495"),
    "7.0.0.0, 7.0.0.2, CF30", make_list('PI87495')
 ),
  severity:SECURITY_WARNING
);
