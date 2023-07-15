#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119837);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2017-14458",
    "CVE-2017-17557",
    "CVE-2018-3842",
    "CVE-2018-3843",
    "CVE-2018-3850",
    "CVE-2018-3853",
    "CVE-2018-10302",
    "CVE-2018-10303"
  );
  script_bugtraq_id(103942, 103999);

  script_name(english:"Foxit PhantomPDF < 8.3.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.6. It is, therefore, affected by multiple vulnerabilities.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3853");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-3850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '8.0',
  'max_version' : '8.3.5.30351',
  'fixed_version' : '8.3.6'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
