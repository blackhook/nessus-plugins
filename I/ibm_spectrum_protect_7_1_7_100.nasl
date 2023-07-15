#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97524);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-8998");
  script_bugtraq_id(96443);
  script_xref(name:"IAVA", value:"2017-A-0049");

  script_name(english:"IBM Spectrum Protect Server 7.1.1.0 - 7.1.7.0 SELECT Command RCE");

  script_set_attribute(attribute:"synopsis", value:
"The backup service installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"IBM Spectrum Protect, formerly known as Tivoli Storage Manager,
installed on the remote host is version 7.1.1.0 through 7.1.7.0. It
is, therefore, affected by a buffer overflow condition when handling
the SELECT command in a SQL query due to improper validation of input.
An authenticated, remote attacker with TSM administrator privileges
can exploit this issue, via a specially crafted SQL query, to cause a
denial of service condition or the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998747");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect Server 7.1.7.100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8998");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include('vcf.inc');

port = get_service(svc:'tsm-agent', exit_on_fail:TRUE);
app = 'IBM Tivoli Storage Manager';

app = vcf::get_app_info(app:app, port:port, service:TRUE);

# Starting with 7.1.3, IBM TSM is known as IBM Spectrum Protect
if (ver_compare(ver:app.version, fix:'7.1.3.0', strict:FALSE) >= 0)
  app.app = 'IBM Spectrum Protect';

constraints = [{'min_version' : '7.1.1.0', 'max_version' : '7.1.7.0', 'fixed_version' : '7.1.7.100'}];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_WARNING,
  strict:FALSE
);
