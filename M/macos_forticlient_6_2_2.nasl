#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131284);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2018-9195");

  script_name(english:"Fortinet FortiClient < 6.2.2 Information Disclosure MitM (FG-IR-18-100) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote macOS host is running a version of Fortinet FortiClient prior to 6.2.2. It is, therefore, affected by an
information disclosure man-in-the-middle vulnerability in the FortiGuard services communication protocol due to the use
of a hardcoded cryptographic key. A remote attacker with knowledge of the hardcoded key can exploit this via the network
to eavesdrop and modify information sent and received from FortiGuard servers.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-100");
  # https://sec-consult.com/en/blog/advisories/weak-encryption-cipher-and-hardcoded-cryptographic-keys-in-fortinet-products/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca502f28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('installed_sw/FortiClient (macOS)');
app_info = vcf::get_app_info(app:'FortiClient (macOS)');

constraints = [
  {'fixed_version' : '6.2.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
