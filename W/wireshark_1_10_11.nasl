#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79251);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2014-8710",
    "CVE-2014-8711",
    "CVE-2014-8712",
    "CVE-2014-8713",
    "CVE-2014-8714"
  );
  script_bugtraq_id(
    71069,
    71070,
    71071,
    71072,
    71073
  );

  script_name(english:"Wireshark 1.10.x < 1.10.11 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Wireshark installed that is
1.10.x prior to 1.10.11. It is, therefore, affected by multiple denial
of service vulnerabilities in following dissectors :

  - AMQP (CVE-2014-8711)
  - NCP (CVE-2014-8712, CVE-2014-8713)
  - SigComp (CVE-2014-8710)
  - TN5250 (CVE-2014-8714)

A remote attacker, using a specially crafted packet, can cause the
application to crash.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-20.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-21.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-22.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-23.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.11.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.10.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.10', 'fixed_version' : '1.10.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
