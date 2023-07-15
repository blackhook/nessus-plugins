#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128148);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-20031",
    "CVE-2018-20032",
    "CVE-2018-20033",
    "CVE-2018-20034"
  );
  script_bugtraq_id(109155);
  script_xref(name:"ICSA", value:"19-192-07");

  script_name(english:"Flexera FlexNet Publisher < 11.16.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A licensing application running on the remote host is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Flexera FlexNet Publisher running on the remote host is
prior to 11.16.2. It is, therefore, affected by multiple vulnerabilities : 

  - A Denial of Service vulnerability related to preemptive item
    deletion in lmgrd and vendor daemon components of FlexNet
    Publisher version 11.16.1.0 and earlier allows a remote attacker
    to send a combination of messages to lmgrd or the vendor daemon,
    causing the heartbeat between lmgrd and the vendor daemon to
    stop, and the vendor daemon to shut down. (CVE-2018-20031)

  - A Denial of Service vulnerability related to message decoding in
    lmgrd and vendor daemon components of FlexNet Publisher version
    11.16.1.0 and earlier allows a remote attacker to send a
    combination of messages to lmgrd or the vendor daemon, causing
    the heartbeat between lmgrd and the vendor daemon to stop, and
    the vendor daemon to shut down. (CVE-2018-20032)

  - A Remote Code Execution vulnerability in lmgrd and vendor daemon
    components of FlexNet Publisher version 11.16.1.0 and earlier
    could allow a remote attacker to corrupt the memory by allocating
    / deallocating memory, loading lmgrd or the vendor daemon and
    causing the heartbeat between lmgrd and the vendor daemon to
    stop. This would force the vendor daemon to shut down.
   (CVE-2018-20033)

  - A Denial of Service vulnerability related to adding an item to a
    list in lmgrd and vendor daemon components of FlexNet Publisher
    version 11.16.1.0 and earlier allows a remote attacker to send a
    combination of messages to lmgrd or the vendor daemon, causing
    the heartbeat between lmgrd and the vendor daemon to stop, and
    the vendor daemon to shut down. (CVE-2018-20034)");
  # https://secuniaresearch.flexerasoftware.com/advisories/85979/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb4f204b");
  # https://www.schneider-electric.com/en/download/document/SEVD-2019-134-04/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd5ba7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FlexNet Publisher 11.16.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flexerasoftware:flexnet_publisher");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flexnet_publisher_detection.nbin", "netscaler_mas_web_detect.nasl");
  script_require_keys("Services/flexnet_publisher");

  exit(0);
}

include('vcf.inc');

# Citrix Netscaler MAS/ADM/ADC not affected; https://support.citrix.com/article/CTX270574
adm = get_kb_item("installed_sw/NetScaler Management and Analytics System");

if (adm)
{
  audit(AUDIT_PACKAGE_NOT_AFFECTED,'FlexNet Publisher');
}


svc = 'flexnet_publisher';
port = get_service(svc:svc, exit_on_fail:TRUE);

app_info = vcf::get_app_info(app:'FlexNet Publisher', kb_ver: svc + '/' + port + '/Version', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {'fixed_version': '11.16.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
