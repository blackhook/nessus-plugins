#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108797);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_xref(name:"IAVA", value:"0001-A-0501");

  script_name(english:"Unsupported Windows OS (remote)");
  script_summary(english:"Determines if the remote Windows OS is unsupported");

  script_set_attribute(attribute:"synopsis", value:
"The remote OS or service pack is no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows is either missing a service pack
or is no longer supported. As a result, it is likely to contain security
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/lifecycle");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a supported service pack or operating system");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported OS.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_keys("Host/OS", "Host/OS/Confidence");
  exit(0);
}

var os = get_kb_item_or_exit("Host/OS");

var confidence = get_kb_item_or_exit("Host/OS/Confidence");

# must be 90+, unless paranoid and 66+
if (confidence < 90)
{
  if (report_paranoia < 2)
    exit(0, "Not sufficiently confident in OS version");
  else if (confidence < 66)
    exit(0, "Not sufficiently confident in OS version");
}

if ("Windows" >!< os)
{
  exit(0, "The remote OS is not Windows");
}

# Checking for extended support kb value set from wmi_win_7_2008r2_esu_status.nbin
if (get_kb_item("WMI/W7_2008R2_ESU"))
exit(0, 'Extended Security Update (ESU) support was detected on the host running ' + os );

# The OS KB item could have multiple potential OS for low confidence scans.
# whe should really split and iterate over these instead.
var oses = split(os, keep:false);

var report = '';
var iter;
var unsupported;

for (iter = 0; iter < max_index(oses); iter++)
{
   unsupported = FALSE;

  # Based off of the following list:
  # https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions
  # And (mostly) the results from os_fingerprint_msrpc.nasl

  if ("Windows 2000" >< oses[iter] ||
      "Windows XP" >< oses[iter] ||
      "Windows Server 2003" >< oses[iter] ||
      "Windows Vista" >< oses[iter] ||
      "Windows 7" >< oses[iter] || "Windows Embedded Standard 7" >< oses[iter] ||
      "Windows Server 2008" >< oses[iter])
  {
    unsupported = TRUE;
    report += '\n\n' + oses[iter] + '\n';
  }
  else if ("Windows 8" >< oses[iter] && "8.1" >!< oses[iter])
  {
    # 8 is unsupported. 8.1 is supported.
    unsupported = TRUE;
    report += '\n\n' + oses[iter] + '\n';
  }

  if (unsupported == TRUE)
  {
    register_unsupported_product(
      product_name : "Microsoft Windows",
      cpe_class    : CPE_CLASS_OS,
      cpe_base     : "microsoft:windows",
      version      : oses[iter]
    );
  }
}

if (empty_or_null(report))
{
  audit(AUDIT_SUPPORTED, "Windows", os);
}
report = '\nThe following Windows version is installed and not supported:' +
         report;

security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
