#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93076);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-7428", "CVE-2016-0245");
  script_bugtraq_id(83479, 83485);

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF20 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.0.0.x prior to 8.0.0.1 CF20. It is, therefore, affected by multiple
vulnerabilities :

  - An open redirect vulnerability exists due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted link, to redirect a user from the intended
    legitimate web site to an arbitrary web site of the
    attacker's choosing. (CVE-2015-7428)
 
  - An XML external entity (XXE) injection vulnerability
    exists due to an incorrectly configured XML parser
    accepting XML external entities from an untrusted
    source. An authenticated, remote attacker can exploit
    this, via specially crafted XML data, to cause a denial
    of service or disclose sensitive information.
    (CVE-2016-0245)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24034497#CF20");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21976358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal version 8.0.0.1 CF20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7428");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/23");

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
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF20",
  severity:SECURITY_WARNING,
  xss:TRUE
);

