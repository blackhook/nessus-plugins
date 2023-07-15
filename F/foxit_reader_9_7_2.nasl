#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135849);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/21");
  script_xref(name:"ZDI", value:"ZDI-CAN-9828");
  script_xref(name:"ZDI", value:"ZDI-CAN-9829");
  script_xref(name:"ZDI", value:"ZDI-CAN-9830");
  script_xref(name:"ZDI", value:"ZDI-CAN-9831");
  script_xref(name:"ZDI", value:"ZDI-CAN-9865");
  script_xref(name:"ZDI", value:"ZDI-CAN-9942");
  script_xref(name:"ZDI", value:"ZDI-CAN-9943");
  script_xref(name:"ZDI", value:"ZDI-CAN-9944");
  script_xref(name:"ZDI", value:"ZDI-CAN-9945");
  script_xref(name:"ZDI", value:"ZDI-CAN-9946");
  script_xref(name:"ZDI", value:"ZDI-CAN-10132");
  script_xref(name:"ZDI", value:"ZDI-CAN-10142");
  script_xref(name:"ZDI", value:"ZDI-CAN-10614");
  script_xref(name:"ZDI", value:"ZDI-CAN-10650");

  script_name(english:"Foxit Reader < 9.7.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by  multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader application installed on the remote Windows host is prior to 9.7.2. It is,
therefore affected by  multiple vulnerabilities: Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.7.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0', 'max_version' : '9.7.1.29511', 'fixed_version' : '9.7.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
