#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142226);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-15708");

  script_name(english:"Apache Synapse < 3.0.1 Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Remote Code Execution vulnerability");
  script_set_attribute(attribute:"description", value:
"All Apache Synapse releases previous to 3.0.1 installed on the remote host are
affected by a Remote Code Execution vulnerability. This can be performed by injecting specially 
crafted serialized objects. And the presence of Apache Commons Collections 3.2.1 
(commons-collections-3.2.1.jar) or previous versions in Synapse distribution makes this exploitable. 
To mitigate the issue, we need to limit RMI access to trusted users only. Further upgrading to 
3.0.1 version will eliminate the risk of having said Commons Collection version. In Synapse 3.0.1,
Commons Collection has been updated to 3.2.2 version.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/102154");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Synapse 3.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:synapse");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("synapse_jar_detection.nbin");
  script_require_keys("installed_sw/Apache Synapse");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Apache Synapse');

constraints = [
  {'fixed_version' : '3.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
