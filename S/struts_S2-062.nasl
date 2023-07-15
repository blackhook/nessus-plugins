#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159667);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/12");

  script_cve_id("CVE-2021-31805");

  script_name(english:"Apache Struts 2.0.0 < 2.5.30 Possible Remote Code Execution vulnerability (S2-062)");

  script_set_attribute(attribute:"synopsis", value:
"Apache Struts installed on the remote host is affected by Possible Remote Code Execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote host is prior to 2.5.30. It is, therefore, affected by a
vulnerability as referenced in the S2-062 advisory.

  - The fix issued for CVE-2020-17530 ( S2-061 ) was incomplete. Still some of the tag's attributes could
    perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax.
    Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security
    degradation. (CVE-2021-31805)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-062");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.30 or later. Alternatively, apply the workaround as referenced in in the vendor's
security bulletin");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
var win_local = ('windows' >< tolower(os));

var app_info = vcf::get_app_info(app:'Apache Struts', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.5.29', 'fixed_version' : '2.5.30' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
