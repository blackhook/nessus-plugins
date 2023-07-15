#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  Date: Wed, 17 Sep 2003 11:19:46 +0200 (CEST)
#  From: Michal Zalewski <lcamtuf@dione.ids.pl>
#  To: bugtraq@securityfocus.com, <vulnwatch@securityfocus.com>,
#      <full-disclosure@netsys.com>
#       Subject: Sendmail 8.12.9 prescan bug (a new one) [CVE-2003-0694]

include("compat.inc");

if (description)
{
  script_id(11838);
  script_version("1.38");
  script_cvs_date("Date: 2018/11/15 20:50:24");

  script_cve_id("CVE-2003-0681", "CVE-2003-0694");
  script_bugtraq_id(8641, 8649);
  script_xref(name:"CERT", value:"108964");
  script_xref(name:"RHSA", value:"2003:283");
  script_xref(name:"SuSE", value:"SUSE-SA");

  script_name(english:"Sendmail < 8.12.10 prescan() Function Remote Overflow");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to multiple buffer overflow attacks.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote Sendmail server is
between 5.79 to 8.12.9.  Such versions are reportedly vulnerable to
remote buffer overflow attacks, one in the 'prescan()' function and
another involving its ruleset processing.  A remote user may be able
to leverage these issues to gain root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2003/Sep/857");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail version 8.12.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0694");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "min_version" : "5.79", "fixed_version" : "8.12.10" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
