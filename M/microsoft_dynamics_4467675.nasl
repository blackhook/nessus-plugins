#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123752);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/30 13:24:47");

  script_cve_id(
    "CVE-2018-8654",
    "CVE-2018-8605",
    "CVE-2018-8606",
    "CVE-2018-8607",
    "CVE-2018-8608",
    "CVE-2018-8609"
    );
  script_bugtraq_id(
    107014,
    105889,
    105890,
    105891,
    105892,
    105894
  );
  
  script_xref(name:"MSKB", value:"4467675");
  script_xref(name:"MSFT", value:"MS19-4467675");

  script_name(english:"Microsoft Dynamics 365 (on-premises) 8.x < 8.2.3.0008 multiple vulnerabilities");
  script_summary(english:"Checks the version of Microsoft Dynamics 365 (on-premises).");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is
affected by multiple vulnerabilities."
);
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Dynamics 365 (on-premises) installed on
the remote Windows host is 8.x prior to 8.2.3.0008. It is,
therefore, affected by multiple vulnerabilities:

  - An elevation of privilege vulnerability exists due to an affected
  server not sanitizing the user input properly. An authenticated,
  remote attacker can exploit this, via sending a specially crafted
  request, to gain elevated privileges. (CVE-2018-8654)

  - A cross-site scripting (XSS) vulnerability exists due to improper
  validation of user-supplied input before returning it to users.
  An unauthenticated, remote attacker can exploit this, by convincing
  a user to click a specially crafted URL, to execute arbitrary script
  code in a user's browser session.
  (CVE-2018-8605, CVE-2018-8606, CVE-2018-8607, CVE-2018-8608)

  - A remote code execution vulnerability exists due to the server
  failing to properly sanitize web requests to an affected
  Dynamics server. An authenticated, remote attacker can exploit
  this to execute arbitrary code in the context of the SQL service
  account. (CVE-2018-8609)
"
);
  # https://support.microsoft.com/en-ie/help/3142345/microsoft-dynamics-365-onpremise-cumulative-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0942482d");
  # https://support.microsoft.com/en-us/help/4467675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c67ead0e");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8654
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27e57acb");
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8605
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e47f6476");
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e136c2fd");
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8607
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90941a01");
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8608
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec939667");
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8609
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb5a1d50");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Dynamics 365 (on-premises) 8.2.3.0008 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8609");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_365");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.3.0008' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
