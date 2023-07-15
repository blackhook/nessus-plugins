##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146430);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id("CVE-2018-20798", "CVE-2018-20799");

  script_name(english:"pfSense < 2.4.4-p3  Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense install is a version prior to 2.4.4-p3. It is,
therefore, affected by multiple vulnerabilities, including the following:

  - In pfSense 2.4.4_1, blocking of source IP addresses on the basis of failed HTTPS authentication is
    inconsistent with blocking of source IP addresses on the basis of failed SSH authentication (the behavior
    does not match the sshguard documentation), which might make it easier for attackers to bypass intended
    access restrictions. (CVE-2018-20799)

  - The expiretable configuration in pfSense 2.4.4_1 establishes block durations that are incompatible with
    the block durations implemented by sshguard, which might make it easier for attackers to bypass intended
    access restrictions. (CVE-2018-20798)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_01.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b623e2bf");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_02.sshguard.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?391d5f25");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_03.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a534c25");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_04.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a49b8ac");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_05.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66f728f6");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_06.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb2ee7ba");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_07.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0697d7a9");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-19_08.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e41356b2");
  script_set_attribute(attribute:"see_also", value:"https://docs.netgate.com/pfsense/en/latest/releases/2-4-4-p3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.4-p3 or later, or apply patches as noted in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netgate:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (!get_kb_item('Host/pfSense')) audit(AUDIT_HOST_NOT, 'pfSense');

app_info = vcf::pfsense::get_app_info();
constraints = [
  {'fixed_version':'2.4.4-p3'}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
