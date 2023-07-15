#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125551);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/04  9:45:00");

  script_cve_id(
    "CVE-2018-7182",
    "CVE-2018-7183",
    "CVE-2018-7184"
  );
  script_bugtraq_id(
    103191,
    103192,
    103351
  );

  script_name(english:"Symantec Content Analysis < 2.3.5.1 affected by Multiple Vulnerabilities (SYMSA1451)");
  script_summary(english:"Checks the version of Symantec Content Analysis");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running a version of Symantec Content Analysis that is
  affected by Multiple Vulnerabilities");
    script_set_attribute(attribute:"description", value:
  "The version of Symantec Content Analysis running on the
  remote host is prior to version 2.3.5.1. It is, therefore,
  affected by multiple vulnerabilities:

    - Buffer overflow in the decodearr function in ntpq in
    ntp 4.2.8p6 through 4.2.8p10 allows remote attackers
    to execute arbitrary code by leveraging an ntpq query
    and sending a response with a crafted array.
    (CVE-2018-7183)

    - The ctl_getitem method in ntpd in ntp-4.2.8p6 before
      4.2.8p11 allows remote attackers to cause a denial of
      service (out-of-bounds read) via a crafted mode 6
      packet with a ntpd instance from 4.2.8p6 through
      4.2.8p10. (CVE-2018-7182)
      
    - ntpd in ntp 4.2.8p4 before 4.2.8p11 drops bad packets
      before updating the 'received' timestamp, which allows
      remote attackers to cause a denial of service
      (disruption) by sending a packet with a zero-origin
      timestamp causing the association to reset and setting
      the contents of the packet as the most recent timestamp.
      (CVE-2018-7184)

    ");
    # https://support.symantec.com/en_US/article.SYMSA1451.html
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?969586e7");
    script_set_attribute(attribute:"solution", value:
  "Refer to vendor advisory (Symantec SYMSA1451) for suggested
  workaround, or upgrade to an unaffected version.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
    script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7183");
    script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
    script_set_attribute(attribute:"exploit_available", value:"true");

    script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/11");
    script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
    script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

    script_set_attribute(attribute:"plugin_type", value:"local");
    script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:content_analysis");
    script_set_attribute(attribute:"cpe", value:"x-cpe:/h:bluecoat:content_analysis");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_family(english:"Misc.");

    script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

    script_dependencies("symantec_content_analysis_local_detect.nbin");
    script_require_keys("installed_sw/Symantec Content Analysis");

    exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');

app_name = 'Symantec Content Analysis';

app_info = vcf::get_app_info(app:app_name, port:0);

constraints = [
  {'min_version': '2.1', 'max_version': '2.2', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.2', 'max_version': '2.3', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.3', 'fixed_version' : '2.3.5.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
