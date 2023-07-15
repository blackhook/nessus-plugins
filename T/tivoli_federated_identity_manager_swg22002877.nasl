#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100422);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-1319", "CVE-2017-1320");
  script_bugtraq_id(98480, 98482);
  script_xref(name:"IAVB", value:"2017-B-0059");

  script_name(english:"IBM Tivoli Federated Identity Manager 6.2.x < 6.2.2 FP17 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM Tivoli Federated Identity Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Federated Identity Manager installed on the
remote Windows host is 6.2.x prior to 6.2.2.17. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to a
    failure to properly use Secure attributes in cookies. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-1319)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-1320)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22002877");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22002871");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Federated Identity Manager version 6.2.2 FP17
(6.2.2.17) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_federated_identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tivoli_federated_identity_manager_installed.nbin");
  script_require_keys("installed_sw/IBM Tivoli Federated Identity Manager");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

app = "IBM Tivoli Federated Identity Manager";

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { "min_version":"6.2.0", "max_version":"6.2.2.16", "fixed_version":"6.2.2.17" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xss":TRUE});
