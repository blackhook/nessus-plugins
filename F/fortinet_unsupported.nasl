#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73531);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0610");

  script_name(english:"Unsupported Fortinet Hardware and Operating System");
  script_summary(english:"Checks for EOL for Hardware and Operating System.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running either obsolete operating system, hardware or both.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Fortinet hardware or operating
system is obsolete and is no longer being maintained or supported by Fortinet.

Lack of support for the hardware implies that future hardware will not
be supported in fixes, replacements and that current and future
operating systems will not work on the hardware.
Lack of support for the operating system implies that no new security
patches will be released by the vendor. As a result, it is likely to
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.fortinet.com/Information/ProductLifeCycle.aspx");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a supported version of the applicable Fortinet operating
system or hardware.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimanager_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortiweb");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimail");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("datetime.inc");

model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
now = unixtime();
device_supported = FALSE;

eol_version = NULL;
eol_date = NULL;

# Array of EOL devices, versions and dates.
eol = make_array(
       "forti(gate|wifi)", make_array(
          "Hardware", make_array(
            "FortiSwitch-5203B", make_array('EOO',"2018-04-16", 'SED',"2022-04-16", 'EOS',"2023-04-16"),
            "FortiController-5902D", make_array('EOO',"2017-08-08", 'SED',"2021-08-08", 'EOS',"2022-08-08"),
            "FortiGate-100", make_array('EOO',"2006-12-31", 'SED',"2008-12-31", 'EOS',"2011-12-31"),
            "FortiGate-1000", make_array('EOO',"2006-08-03", 'SED',"2008-08-03", 'EOS',"2011-08-03"),
            "FortiGate-1000A", make_array('EOO',"2010-02-25", 'SED',"2014-02-25", 'EOS',"2015-02-25"),
            "FortiGate-1000A-LENC", make_array('EOO',"2011-09-30", 'SED',"2015-09-30", 'EOS',"2016-09-30"),
            "FortiGate-1000AFA2", make_array('EOO',"2010-02-25", 'SED',"2014-02-25", 'EOS',"2015-02-25"),
            "FortiGate-1000C", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.6'),
            "FortiGate-1000C-DC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-1000C-LENC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-1000C-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-100A", make_array('EOO',"2009-04-15", 'SED',"2013-04-15", 'EOS',"2014-04-15"),
            "FortiGate-100D", make_array('EOO',"2018-07-26", 'SED',"2022-07-26", 'EOS',"2023-07-26"),
            "FortiGate-100D-G", make_array('EOO',"2017-08-29", 'SED',"2021-08-29", 'EOS',"2022-08-29"),
            "FortiGate-100D-LENC", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-110C", make_array('EOO',"2013-08-20", 'SED',"2017-08-20", 'EOS',"2018-08-20", 'EOSS','5.2'),
            "FortiGate-110C-G", make_array('EOO',"2014-04-14", 'SED',"2018-04-14", 'EOS',"2019-04-14"),
            "FortiGate-111C", make_array('EOO',"2013-08-20", 'SED',"2017-08-20", 'EOS',"2018-08-20", 'EOSS','5.2'),
            "FortiGate-111C-G", make_array('EOO',"2014-04-14", 'SED',"2018-04-14", 'EOS',"2019-04-14"),
            "FortiGate-1240B", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-1240B-DC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-1240B-G", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-1240B-LENC-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-140D", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-140D-POE", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-140D-POE-T1", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-140E", make_array('EOO',"2019-03-14", 'SED',"2023-03-14", 'EOS',"2024-03-14"),
            "FortiGate-1500D-DC", make_array('EOO',"2020-04-10", 'SED',"2024-04-10", 'EOS',"2025-04-10"),
            "FortiGate-1500D-DC-USG", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-200", make_array('EOO',"2006-12-31", 'SED',"2010-12-31", 'EOS',"2011-12-31"),
            "FortiGate-200-HD", make_array('EOO',"2006-12-31", 'SED',"2010-12-31", 'EOS',"2011-12-31"),
            "FortiGate-200A", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiGate-200A-HD", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiGate-200B", make_array('EOO',"2015-04-01", 'SED',"2019-04-01", 'EOS',"2020-04-01", 'EOSS','5.2'),
            "FortiGate-200B-G", make_array('EOO',"2015-04-01", 'SED',"2019-04-01", 'EOS',"2020-04-01"),
            "FortiGate-200B-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-200B-LENC-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiGate-200B-POE", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-200B-POE-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-200D", make_array('EOO',"2018-05-22", 'SED',"2022-05-22", 'EOS',"2023-05-22"),
            "FortiGate-200D-LENC", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-200D-POE", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiGate-200D-POE-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiGate-20C", make_array('EOO',"2014-08-16", 'SED',"2018-08-16", 'EOS',"2019-08-16", 'EOSS','5.2'),
            "FortiGate-20C-ADSL-A", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-20C-LENC", make_array('EOO',"2016-06-16", 'SED',"2020-06-16", 'EOS',"2021-06-16"),
            "FortiGate-224B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-240D-LENC", make_array('EOO',"2019-04-16", 'SED',"2023-04-16", 'EOS',"2024-04-16"),
            "FortiGate-240D-POE", make_array('EOO',"2019-04-16", 'SED',"2023-04-16", 'EOS',"2024-04-16"),
            "FortiGate-240D-POE-USG", make_array('EOO',"2019-04-16", 'SED',"2023-04-16", 'EOS',"2024-04-16"),
            "FortiGate-280D-POE-Gen2", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15"),
            "FortiGate-280D-POE-USG", make_array('EOO',"2017-10-15", 'SED',"2021-10-15", 'EOS',"2022-10-15"),
            "FortiGate-300", make_array('EOO',"2006-12-31", 'SED',"2011-12-31", 'EOS',"2012-12-31"),
            "FortiGate-3000", make_array('EOO',"2007-09-13", 'SED',"2009-09-13", 'EOS',"2012-09-13"),
            "FortiGate-3000D-DC", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15"),
            "FortiGate-3000D-DC-USG", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-300A", make_array('EOO',"2011-09-30", 'SED',"2015-09-30", 'EOS',"2016-09-30"),
            "FortiGate-300A-HD", make_array('EOO',"2011-09-30", 'SED',"2015-09-30", 'EOS',"2016-09-30"),
            "FortiGate-300C", make_array('EOO',"2016-08-20", 'SED',"2020-08-20", 'EOS',"2021-08-20", 'EOSS','5.2'),
            "FortiGate-300C-G", make_array('EOO',"2016-08-20", 'SED',"2020-08-20", 'EOS',"2021-08-20"),
            "FortiGate-300C-G-LENC", make_array('EOO',"2016-08-20", 'SED',"2020-08-20", 'EOS',"2021-08-20"),
            "FortiGate-300C-LENC", make_array('EOO',"2016-08-20", 'SED',"2020-08-20", 'EOS',"2021-08-20", 'EOSS','5.2'),
            "FortiGate-300D", make_array('EOO',"2018-10-11", 'SED',"2022-10-11", 'EOS',"2023-10-11"),
            "FortiGate-300D-LENC", make_array('EOO',"2018-10-11", 'SED',"2022-10-11", 'EOS',"2023-10-11"),
            "FortiGate-300D-USG", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3016B", make_array('EOO',"2013-08-20", 'SED',"2017-08-20", 'EOS',"2018-08-20", 'EOSS','5.2'),
            "FortiGate-3016B-G", make_array('EOO',"2014-04-14", 'SED',"2018-04-14", 'EOS',"2019-04-14"),
            "FortiGate-3040B", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-3040B-DC", make_array('EOO',"2017-11-23", 'SED',"2021-11-23", 'EOS',"2022-11-23"),
            "FortiGate-3040B-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-3040B-USG", make_array('EOO',"2017-07-06", 'SED',"2021-07-06", 'EOS',"2022-07-06"),
            "FortiGate-30B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-30D", make_array('EOO',"2016-11-30", 'SED',"2020-11-30", 'EOS',"2021-11-30"),
            "FortiGate-30D-POE", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiGate-30E-3G4G-INTL", make_array('EOO',"2019-07-18", 'SED',"2023-07-18", 'EOS',"2024-07-18"),
            "FortiGate-30E-3G4g", make_array('EOO',"2018-11-22", 'SED',"2022-11-22", 'EOS',"2023-11-22"),
            "FortiGate-3100D-DC", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-310B", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-310B-DC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-310B-DC-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-310B-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiGate-310B-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-310B-LENC-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiGate-311B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-311B-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-3140B", make_array('EOO',"2017-01-15", 'SED',"2021-01-15", 'EOS',"2022-01-15", 'EOSS','5.2'),
            "FortiGate-3140B-DC", make_array('EOO',"2017-01-15", 'SED',"2021-01-15", 'EOS',"2022-01-15"),
            "FortiGate-3140B-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-3140B-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-3200D-DC", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-3240C", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.6'),
            "FortiGate-3240C-DC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-3600", make_array('EOO',"2013-05-17", 'SED',"2017-05-17", 'EOS',"2018-05-17"),
            "FortiGate-3600A", make_array('EOO',"2013-05-17", 'SED',"2017-05-17", 'EOS',"2018-05-17"),
            "FortiGate-3600C", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.6'),
            "FortiGate-3600C-DC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-3600C-LENC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-3600LX2", make_array('EOO',"2011-06-19", 'SED',"2015-06-19", 'EOS',"2016-06-19"),
            "FortiGate-3600LX4", make_array('EOO',"2011-06-19", 'SED',"2015-06-19", 'EOS',"2016-06-19"),
            "FortiGate-3700D-DC-NEBS", make_array('EOO',"2019-02-28", 'SED',"2023-02-28", 'EOS',"2024-02-28"),
            "FortiGate-3700D-DC-NEBS-USG", make_array('EOO',"2019-02-28", 'SED',"2023-02-28", 'EOS',"2024-02-28"),
            "FortiGate-3700D-NEBS", make_array('EOO',"2019-02-28", 'SED',"2023-02-28", 'EOS',"2024-02-28"),
            "FortiGate-3700DX", make_array('EOO',"2018-11-22", 'SED',"2022-11-22", 'EOS',"2023-11-22"),
            "FortiGate-3810A-DC", make_array('EOO',"2015-07-01", 'SED',"2019-07-01", 'EOS',"2020-07-01", 'EOSS','5.2'),
            "FortiGate-3810A-DC-G", make_array('EOO',"2015-07-01", 'SED',"2019-07-01", 'EOS',"2020-07-01"),
            "FortiGate-3810A-E4", make_array('EOO',"2015-07-01", 'SED',"2019-07-01", 'EOS',"2020-07-01", 'EOSS','5.2'),
            "FortiGate-3810A-E4-G", make_array('EOO',"2015-07-01", 'SED',"2019-07-01", 'EOS',"2020-07-01"),
            "FortiGate-3810A-LENC", make_array('EOO',"2015-07-01", 'SED',"2019-07-01", 'EOS',"2020-07-01", 'EOSS','5.2'),
            "FortiGate-3810D", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3810D-DC", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3810D-DC-NEBS", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3810D-NEBS", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3810D-USG", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3815D", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-3815D-DC", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3815D-DC-NEBS", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3815D-NEBS", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-3950B", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01", 'EOSS','5.2'),
            "FortiGate-3950B-DC", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01"),
            "FortiGate-3950B-DC-R", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01"),
            "FortiGate-3950B-G", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01"),
            "FortiGate-3950B-LENC", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01", 'EOSS','5.2'),
            "FortiGate-3950B-R", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01"),
            "FortiGate-3950B-USG", make_array('EOO',"2016-10-01", 'SED',"2020-10-01", 'EOS',"2021-10-01"),
            "FortiGate-3951B", make_array('EOO',"2012-02-17", 'SED',"2016-02-17", 'EOS',"2017-02-17", 'EOSS','5.2'),
            "FortiGate-3951B-DC", make_array('EOO',"2012-02-17", 'SED',"2016-02-17", 'EOS',"2017-02-17", 'EOSS','5.2'),
            "FortiGate-400", make_array('EOO',"2006-12-31", 'SED',"2008-12-31", 'EOS',"2011-12-31"),
            "FortiGate-4000P", make_array('EOO',"2006-02-03", 'SED',"2008-02-03", 'EOS',"2011-02-03"),
            "FortiGate-4000S", make_array('EOO',"2006-02-03", 'SED',"2008-02-03", 'EOS',"2011-02-03"),
            "FortiGate-400A", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiGate-400A-HD", make_array('EOO',"2011-09-30", 'SED',"2015-09-30", 'EOS',"2016-09-30"),
            "FortiGate-400D", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-400D-LENC", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-400D-USG", make_array('EOO',"2018-05-29", 'SED',"2022-05-29", 'EOS',"2023-05-29"),
            "FortiGate-4010B", make_array('EOO',"2006-02-03", 'SED',"2008-02-03", 'EOS',"2011-02-03"),
            "FortiGate-40C", make_array('EOO',"2018-01-14", 'SED',"2022-01-14", 'EOS',"2023-01-14", 'EOSS','5.2'),
            "FortiGate-40C-LENC", make_array('EOO',"2016-06-16", 'SED',"2020-06-16", 'EOS',"2021-06-16"),
            "FortiGate-50", make_array('EOO',"2004-06-01", 'SED',"2006-06-01", 'EOS',"2009-06-01"),
            "FortiGate-500", make_array('EOO',"2006-12-31", 'SED',"2008-12-31", 'EOS',"2011-12-31"),
            "FortiGate-5001 SX", make_array('EOO',"2017-04-15", 'SED',"2021-04-15", 'EOS',"2022-04-15"),
            "FortiGate-5001-FA2", make_array('EOO',"2012-02-17", 'SED',"2016-02-17", 'EOS',"2017-02-17"),
            "FortiGate-5001-SX-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiGate-5001A-DW", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-5001A-DW-G", make_array('EOO',"2017-07-14", 'SED',"2021-07-14", 'EOS',"2022-07-14"),
            "FortiGate-5001A-DW-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-5001A-SW", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-5001A-SW-G", make_array('EOO',"2017-07-14", 'SED',"2021-07-14", 'EOS',"2022-07-14"),
            "FortiGate-5001B", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13"),
            "FortiGate-5001B-USG", make_array('EOO',"2017-07-14", 'SED',"2021-07-14", 'EOS',"2022-07-14"),
            "FortiGate-5001C", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15", 'EOSS','5.6'),
            "FortiGate-5001C-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiGate-5001FA2-LENC", make_array('EOO',"2011-12-30", 'SED',"2015-12-30", 'EOS',"2016-12-30"),
            "FortiGate-5002FB2", make_array('EOO',"2007-04-15", 'SED',"2011-12-31", 'EOS',"2012-12-31"),
            "FortiGate-5005FA2", make_array('EOO',"2012-06-13", 'SED',"2016-06-13", 'EOS',"2017-06-13"),
            "FortiGate-500A", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiGate-500A-HD", make_array('EOO',"2011-09-30", 'SED',"2015-09-30", 'EOS',"2016-09-30"),
            "FortiGate-500D", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-500D-LENC", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiGate-5050-DC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-5050-DC-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-5050FA", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-5050SAP", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-5050SM", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-50A", make_array('EOO',"2007-04-17", 'SED',"2009-04-17", 'EOS',"2012-04-17"),
            "FortiGate-50B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-50B-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-50B-LENC", make_array('EOO',"2011-12-30", 'SED',"2015-12-30", 'EOS',"2016-12-30"),
            "FortiGate-5101C", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-5101C-G", make_array('EOO',"2017-07-14", 'SED',"2021-07-14", 'EOS',"2022-07-14"),
            "FortiGate-5101C-LENC", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13", 'EOSS','5.2'),
            "FortiGate-5140-DC", make_array('EOO',"2012-02-17", 'SED',"2016-02-17", 'EOS',"2017-02-17"),
            "FortiGate-51B", make_array('EOO',"2014-12-31", 'SED',"2018-12-31", 'EOS',"2019-12-31"),
            "FortiGate-51B-LENC", make_array('EOO',"2011-12-30", 'SED',"2015-12-30", 'EOS',"2016-12-30"),
            "FortiGate-52E", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15"),
            "FortiGate-52E-USG", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-60", make_array('EOO',"2008-11-21", 'SED',"2012-11-21", 'EOS',"2013-11-21"),
            "FortiGate-600C", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.6'),
            "FortiGate-600C-DC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-600C-DC-G", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-600C-LENC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-600C-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-600D", make_array('EOO',"2019-10-14", 'SED',"2023-10-14", 'EOS',"2024-10-14"),
            "FortiGate-60ADSL", make_array('EOO',"2007-11-29", 'SED',"2011-11-29", 'EOS',"2012-11-29"),
            "FortiGate-60B", make_array('EOO',"2010-10-06", 'SED',"2014-10-06", 'EOS',"2015-10-06"),
            "FortiGate-60C", make_array('EOO',"2015-01-21", 'SED',"2019-01-21", 'EOS',"2020-01-21", 'EOSS','5.2'),
            "FortiGate-60C-G", make_array('EOO',"2016-06-16", 'SED',"2020-06-16", 'EOS',"2021-06-16"),
            "FortiGate-60C-POE", make_array('EOO',"2016-06-16", 'SED',"2020-06-16", 'EOS',"2021-06-16", 'EOSS','5.2'),
            "FortiGate-60C-SFP", make_array('EOO',"2014-12-31", 'SED',"2018-12-31", 'EOS',"2019-12-31", 'EOSS','5.2'),
            "FortiGate-60D", make_array('EOO',"2018-09-23", 'SED',"2022-09-23", 'EOS',"2023-09-23"),
            "FortiGate-60D-3G4G-VZW", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14", 'EOSS','5.2'),
            "FortiGate-60D-LENC", make_array('EOO',"2018-09-27", 'SED',"2022-09-27", 'EOS',"2023-09-27"),
            "FortiGate-60D-POE", make_array('EOO',"2018-05-29", 'SED',"2022-05-29", 'EOS',"2023-05-29"),
            "FortiGate-60D-POE-USG", make_array('EOO',"2018-05-29", 'SED',"2022-05-29", 'EOS',"2023-05-29"),
            "FortiGate-60D-USG", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-60M", make_array('EOO',"2007-04-17", 'SED',"2009-04-17", 'EOS',"2012-04-17"),
            "FortiGate-620B", make_array('EOO',"2016-08-02", 'SED',"2020-08-02", 'EOS',"2021-08-02", 'EOSS','5.2'),
            "FortiGate-620B-DC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-620B-DC-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-620B-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiGate-620B-LENC", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-621B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.2'),
            "FortiGate-621B-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-7040E", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-1", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-1-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-2", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-2-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-3", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-3-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-4", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-4-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-5", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-5-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-6", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-6-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7040E-USG", make_array('EOO',"2017-12-14", 'SED',"2021-12-14", 'EOS',"2022-12-14"),
            "FortiGate-7060E-1", make_array('EOO',"2017-10-15", 'SED',"2021-10-15", 'EOS',"2022-10-15"),
            "FortiGate-7060E-3", make_array('EOO',"2017-10-15", 'SED',"2021-10-15", 'EOS',"2022-10-15"),
            "FortiGate-70D", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiGate-70D-LENC", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiGate-70D-POE", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiGate-800", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-800-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-800C", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.6'),
            "FortiGate-800C-DC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-800C-LENC", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-800C-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiGate-800F", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiGate-80C", make_array('EOO',"2018-01-14", 'SED',"2022-01-14", 'EOS',"2023-01-14", 'EOSS','5.6'),
            "FortiGate-80C-G", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiGate-80C-LENC", make_array('EOO',"2016-06-16", 'SED',"2020-06-16", 'EOS',"2021-06-16"),
            "FortiGate-80CM", make_array('EOO',"2018-01-14", 'SED',"2022-01-14", 'EOS',"2023-01-14", 'EOSS','5.6'),
            "FortiGate-80CM-G", make_array('EOO',"2017-11-23", 'SED',"2021-11-23", 'EOS',"2022-11-23"),
            "FortiGate-80D", make_array('EOO',"2018-04-16", 'SED',"2022-04-16", 'EOS',"2023-04-16"),
            "FortiGate-82C", make_array('EOO',"2011-07-17", 'SED',"2015-07-17", 'EOS',"2016-07-17"),
            "FortiGate-90D", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiGate-90D-LENC", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiGate-90D-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiGate-90E", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15"),
            "FortiGate-91E", make_array('EOO',"2018-05-29", 'SED',"2022-05-29", 'EOS',"2023-05-29", 'EOSS','5.6'),
            "FortiGate-91E-USG", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiGate-92D", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiGate-94D-POE", make_array('EOO',"2019-01-14", 'SED',"2023-01-14", 'EOS',"2024-01-14"),
            "FortiGate-98D-POE", make_array('EOO',"2020-04-15", 'SED',"2024-04-15", 'EOS',"2025-04-15"),
            "FortiGate-VM", make_array('EOO',"2017-10-31", 'SED',"2021-10-31", 'EOS',"2022-10-31"),
            "FortiGate-VM USG", make_array('EOO',"2018-03-29", 'SED',"2022-03-29", 'EOS',"2023-03-29"),
            "FortiGate-VM-USG", make_array('EOO',"2018-03-29", 'SED',"2022-03-29", 'EOS',"2023-03-29"),
            "FortiGate-VMX", make_array('EOO',"2018-05-22", 'SED',"2022-05-22", 'EOS',"2023-05-22"),
            "FortiGate-VMX-v2", make_array('EOO',"2018-05-22", 'SED',"2022-05-22", 'EOS',"2023-05-22"),
            "FortiGateRugged-100C", make_array('EOO',"2017-04-16", 'SED',"2021-04-16", 'EOS',"2022-04-16", 'EOSS','5.2'),
            "FortiWiFi-20C", make_array('EOO',"2014-08-16", 'SED',"2018-08-16", 'EOS',"2019-08-16", 'EOSS','5.2'),
            "FortiWiFi-20C-ADSL-A", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiWiFi-30B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiWiFi-30D", make_array('EOO',"2016-11-30", 'SED',"2020-11-30", 'EOS',"2021-11-30"),
            "FortiWiFi-30D-POE", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiWiFi-30E-3G4G-INTL", make_array('EOO',"2019-07-18", 'SED',"2023-07-18", 'EOS',"2024-07-18"),
            "FortiWiFi-30E-3G4G-NAM", make_array('EOO',"2018-11-22", 'SED',"2022-11-22", 'EOS',"2023-11-22"),
            "FortiWiFi-40C", make_array('EOO',"2018-04-16", 'SED',"2022-04-16", 'EOS',"2023-04-16", 'EOSS','5.2'),
            "FortiWiFi-50B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiWiFi-50B-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiWiFi-60", make_array('EOO',"2007-07-17", 'SED',"2009-07-17", 'EOS',"2012-07-17"),
            "FortiWiFi-60A", make_array('EOO',"2007-11-29", 'SED',"2011-12-31", 'EOS',"2012-12-31"),
            "FortiWiFi-60AM", make_array('EOO',"2007-10-16", 'SED',"2011-12-31", 'EOS',"2012-12-31"),
            "FortiWiFi-60B", make_array('EOO',"2010-10-06", 'SED',"2014-10-06", 'EOS',"2015-10-06"),
            "FortiWiFi-60C", make_array('EOO',"2015-01-21", 'SED',"2019-01-21", 'EOS',"2020-01-21", 'EOSS','5.2'),
            "FortiWiFi-60C-G", make_array('EOO',"2017-07-18", 'SED',"2021-07-18", 'EOS',"2022-07-18"),
            "FortiWiFi-60CM", make_array('EOO',"2017-05-29", 'SED',"2021-05-29", 'EOS',"2022-05-29"),
            "FortiWiFi-60CM-3G4G-B", make_array('EOO',"2014-12-31", 'SED',"2018-12-31", 'EOS',"2019-12-31", 'EOSS','5.2'),
            "FortiWiFi-60CM-G", make_array('EOO',"2017-11-23", 'SED',"2021-11-23", 'EOS',"2022-11-23"),
            "FortiWiFi-60CX-ADSL-A", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16", 'EOSS','5.2'),
            "FortiWiFi-60CX-ADSL-A-G", make_array('EOO',"2017-07-16", 'SED',"2021-07-16", 'EOS',"2022-07-16"),
            "FortiWiFi-60D", make_array('EOO',"2018-05-08", 'SED',"2022-05-08", 'EOS',"2023-05-08"),
            "FortiWiFi-60D-3G4G-VZW", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14", 'EOSS','5.2'),
            "FortiWiFi-60D-3G4G-VZW-USG", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOSS',"2023-10-14"),
            "FortiWiFi-60D-POE", make_array('EOO',"2018-06-24", 'SED',"2022-06-24", 'EOS',"2023-06-24"),
            "FortiWiFi-60D-USG", make_array('EOO',"2018-05-29", 'SED',"2022-05-29", 'EOS',"2023-05-29"),
            "FortiWiFi-80CM", make_array('EOO',"2018-04-16", 'SED',"2022-04-16", 'EOS',"2023-04-16", 'EOSS','5.6'),
            "FortiWiFi-80CM-G", make_array('EOO',"2017-11-23", 'SED',"2021-11-23", 'EOS',"2022-11-23"),
            "FortiWiFi-81CM", make_array('EOO',"2012-02-17", 'SED',"2016-02-17", 'EOS',"2017-02-17", 'EOSS','5.6'),
            "FortiWiFi-90D", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiWiFi-90D-Gen2-J", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiWiFi-90D-I", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiWiFi-90D-K", make_array('EOO',"2018-10-14", 'SED',"2022-10-14", 'EOS',"2023-10-14"),
            "FortiWiFi-90D-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiWiFi-92D", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15")
          ),
          "OS", make_array(
            "^3\.3\.", make_list("2009-10-02", "3.0 MR 3"),
            "^3\.4\.", make_list("2009-12-29", "3.0 MR 4"),
            "^3\.5\.", make_list("2010-07-03", "3.0 MR 5"),
            "^3\.6\.", make_list("2011-02-04", "3.0 MR 6"),
            "^3\.7\.", make_list("2011-07-18", "3.0 MR 7"),
            "^4\.0\.", make_list("2012-02-24", "4.0"),
            "^4\.1\.", make_list("2012-08-24", "4.0 MR 1"),
            "^4\.2\.", make_list("2013-04-01", "4.0 MR 2"),
            "^4\.3\.", make_list("2014-03-19", "4.0 MR 3"),
            "^5\.0\.", make_list("2017-05-01", "5.0"),
            "^5\.2\.", make_list("2018-12-13", "5.0 MR 2"),
            "^5\.4\.", make_list("2020-06-21", "5.0 MR 4"),
            "^5\.6\.", make_list("2021-09-30", "5.0 MR 6"),
            "^6\.0\.", make_list("2022-09-29", "6.0"),
            "^6\.2\.", make_list("2023-09-28", "6.2")
          )
        ),
        "fortianalyzer", make_array(
          "Hardware", make_array(
            "FL-400D2", make_array('EOO',"2014-08-16", 'SED',"", 'EOS',"2019-08-16"),
            "FortiAnalyzer-1000B", make_array('EOO',"2010-11-29", 'SED',"2014-11-29", 'EOS',"2015-11-29"),
            "FortiAnalyzer-1000C", make_array('EOO',"2014-01-08", 'SED',"2018-01-08", 'EOS',"2019-01-08", 'EOSS','5.4'),
            "FortiAnalyzer-1000C-G", make_array('EOO',"2014-04-14", 'SED',"2018-04-14", 'EOS',"2019-04-14"),
            "FortiAnalyzer-1000D", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','6.0'),
            "FortiAnalyzer-1000D-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-1000E", make_array('EOO',"2020-03-22", 'SED',"2024-03-22", 'EOS',"2025-03-22"),
            "FortiAnalyzer-1000E-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiAnalyzer-100A", make_array('EOO',"2007-03-01", 'SED',"2009-03-01", 'EOS',"2012-03-01"),
            "FortiAnalyzer-100B", make_array('EOO',"2011-12-30", 'SED',"2015-12-30", 'EOS',"2016-12-30"),
            "FortiAnalyzer-100C", make_array('EOO',"2012-10-25", 'SED',"2016-10-25", 'EOS',"2017-10-25"),
            "FortiAnalyzer-2000", make_array('EOO',"2008-12-14", 'SED',"2012-12-14", 'EOS',"2013-12-14"),
            "FortiAnalyzer-2000A", make_array('EOO',"2009-09-17", 'SED',"2013-09-17", 'EOS',"2014-09-17"),
            "FortiAnalyzer-2000A-HD500", make_array('EOO',"2009-09-16", 'SED',"2013-09-16", 'EOS',"2014-09-16"),
            "FortiAnalyzer-2000B", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','5.4'),
            "FortiAnalyzer-2000B-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-2000E-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiAnalyzer-200D", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS', '6.0'),
            "FortiAnalyzer-3000D", make_array('EOO',"2017-02-02", 'SED',"2021-02-02", 'EOS',"2022-02-02", 'EOSS','6.0'),
            "FortiAnalyzer-3000D-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-3000E", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-3000E-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-300D", make_array('EOO',"2016-09-01", 'SED',"2020-09-01", 'EOS',"2021-09-01", 'EOSS', '6.0'),
            "FortiAnalyzer-300D-USG", make_array('EOO',"2017-02-02", 'SED',"2021-02-02", 'EOS',"2022-02-02"),
            "FortiAnalyzer-3500E", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-3500E-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-3500F", make_array('EOO',"2018-11-06", 'SED',"2022-11-06", 'EOS',"2023-11-06"),
            "FortiAnalyzer-3500F-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiAnalyzer-3900E", make_array('EOO',"2018-06-26", 'SED',"2022-06-26", 'EOS',"2023-06-26"),
            "FortiAnalyzer-400", make_array('EOO',"2007-07-17", 'SED',"2009-07-17", 'EOS',"2012-07-17"),
            "FortiAnalyzer-4000", make_array('EOO',"2007-03-01", 'SED',"2009-03-01", 'EOS',"2012-03-01"),
            "FortiAnalyzer-4000A", make_array('EOO',"2008-06-13", 'SED',"2012-06-13", 'EOS',"2013-06-13"),
            "FortiAnalyzer-4000A-HD500", make_array('EOO',"2010-12-26", 'SED',"2014-12-26", 'EOS',"2015-12-26"),
            "FortiAnalyzer-4000B", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09", 'EOSS','5.4'),
            "FortiAnalyzer-4000B-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiAnalyzer-400B", make_array('EOO',"2012-06-13", 'SED',"2016-06-13", 'EOS',"2017-06-13"),
            "FortiAnalyzer-400C", make_array('EOO',"2013-07-25", 'SED',"2017-07-25", 'EOS',"2018-07-25"),
            "FortiAnalyzer-800", make_array('EOO',"2007-10-16", 'SED',"2011-10-16", 'EOS',"2012-10-16"),
            "FortiAnalyzer-800B", make_array('EOO',"2009-04-28", 'SED',"2013-04-28", 'EOS',"2014-04-28"),
            "FortiAnalyzer-BigData-4000D", make_array('EOO',"2019-05-09", 'SED',"2023-05-09", 'EOS',"2024-05-09"),
            "FortiAnalyzer-BigData-4100D", make_array('EOO',"2017-07-09", 'SED',"2021-07-09", 'EOS',"2022-07-09"),
            "FortiAnalyzer-VM", make_array('EOO',"2018-06-28", 'SED',"2022-06-28", 'EOS',"2023-06-28"),
            "FortiAnalyzer-VM-AWS-USG", make_array('EOO',"2017-09-26", 'SED',"2021-09-26", 'EOS',"2022-09-26"),
            "FortiAnalyzer-VM-USG", make_array('EOO',"2017-09-26", 'SED',"2021-09-26", 'EOS',"2022-09-26"),
            "FortiAnalyzer-VM100", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-VM1000", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-VM2000", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-VM400", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-VM4000", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-VMUNL", make_array('EOO',"2012-10-01", 'SED',"2016-10-01", 'EOS',"2017-10-01"),
            "FortiAnalyzer-bigdata-4000D", make_array('EOO',"2019-05-09", 'SED',"2023-05-09", 'EOS',"2024-05-09"),
            "FortiAnalyzer-bigdata-4100D", make_array('EOO',"2017-07-09", 'SED',"2021-07-09", 'EOS',"2022-07-09"),
            "FortiMonitor-3000D", make_array('EOO',"2019-06-06", 'SED',"2023-06-06", 'EOS',"2024-06-06"),
            "fortianlayzer-VM", make_array('EOO',"2018-06-28", 'SED',"2022-06-28", 'EOS',"2023-06-28")
          ),
          "OS", make_array(
            "^3\.3\.", make_list("2009-10-02", "3.0 MR 3"),
            "^3\.4\.", make_list("2010-01-12", "3.0 MR 4"),
            "^3\.5\.", make_list("2010-07-12", "3.0 MR 5"),
            "^3\.6\.", make_list("2011-02-04", "3.0 MR 6"),
            "^3\.7\.", make_list("2011-08-06", "3.0 MR 7"),
            "^4\.0\.", make_list("2012-02-25", "4.0"),
            "^4\.1\.", make_list("2012-08-24", "4.0 MR 1"),
            "^4\.2\.", make_list("2013-04-07", "4.0 MR 2"),
            "^4\.3\.", make_list("2014-06-30", "4.0 MR 3"),
            "^5\.0\.", make_list("2017-05-01", "5.0"),
            "^5\.2\.", make_list("2019-03-04", "5.0 MR 2"),
            "^5\.4\.", make_list("2020-08-17", "5.0 MR 4"),
            "^5\.6\.", make_list("2022-01-27", "5.0 MR 6"),
            "^6\.0\.", make_list("2022-10-18", "6.0"),
            "^6\.2\.", make_list("2023-10-11", "6.2")
          )
       ),
       "fortimanager", make_array(
          "Hardware", make_array(
            "FortiManager-100", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17", 'EOSS','4.3'),
            "FortiManager-1000C", make_array('EOO',"2014-01-08", 'SED',"2018-01-08", 'EOS',"2019-01-08", 'EOSS','5.4'),
            "FortiManager-1000C-G", make_array('EOO',"2014-04-14", 'SED',"2018-04-14", 'EOS',"2019-04-14"),
            "FortiManager-1000D", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17", 'EOSS','6.0'),
            "FortiManager-1000D-USG", make_array('EOO',"2017-02-02", 'SED',"2021-02-02", 'EOS',"2022-02-02"),
            "FortiManager-100C", make_array('EOO',"2012-10-25", 'SED',"2016-10-25", 'EOS',"2017-10-25", 'EOSS','5.2'),
            "FortiManager-2000E-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiManager-3000", make_array('EOO',"2008-10-16", 'SED',"2012-10-16", 'EOS',"2013-10-16", 'EOSS','4.3'),
            "FortiManager-3000B", make_array('EOO',"2010-10-06", 'SED',"2014-10-06", 'EOS',"2015-10-06"),
            "FortiManager-3000C", make_array('EOO',"2017-09-26", 'SED',"2021-09-26", 'EOS',"2022-09-26", 'EOSS','5.4'),
            "FortiManager-3000F-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiManager-300D", make_array('EOO',"2016-09-01", 'SED',"2020-09-01", 'EOS',"2021-09-01", 'EOSS','6.0'),
            "FortiManager-300D-USG", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiManager-300E-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiManager-3900E", make_array('EOO',"2018-06-26", 'SED',"2022-06-26", 'EOS',"2023-06-26"),
            "FortiManager-400", make_array('EOO',"2005-04-15", 'SED',"2007-04-15", 'EOS',"2008-04-15"),
            "FortiManager-4000D-USG", make_array('EOO',"2017-02-02", 'SED',"2021-02-02", 'EOS',"2022-02-02"),
            "FortiManager-4000E", make_array('EOO',"2017-01-17", 'SED',"2021-01-17", 'EOS',"2022-01-17"),
            "FortiManager-4000E-USG", make_array('EOO',"2017-02-02", 'SED',"2021-02-02", 'EOS',"2022-02-02"),
            "FortiManager-400A", make_array('EOO',"2011-06-19", 'SED',"2015-06-19", 'EOS',"2016-06-19", 'EOSS','4.3'),
            "FortiManager-400B", make_array('EOO',"2012-06-21", 'SED',"2016-06-21", 'EOS',"2017-06-21"),
            "FortiManager-400C", make_array('EOO',"2013-07-25", 'SED',"2017-07-25", 'EOS',"2018-07-25", 'EOSS','5.2'),
            "FortiManager-400E-USG", make_array('EOO',"2018-07-15", 'SED',"2022-07-15", 'EOS',"2023-07-15"),
            "FortiManager-5001A", make_array('EOO',"2014-08-16", 'SED',"2018-08-16", 'EOS',"2019-08-16"),
            "FortiManager-VM", make_array('EOO',"2018-06-28", 'SED',"2022-06-28", 'EOS',"2023-06-28"),
            "FortiManager-VM-AWS-USG", make_array('EOO',"2017-09-26", 'SED',"2021-09-26", 'EOS',"2022-09-26"),
            "FortiManager-VM-USG", make_array('EOO',"2017-09-26", 'SED',"2021-09-26", 'EOS',"2022-09-26")
          ),
          "OS", make_array(
            "^3\.3\.", make_list("2010-01-31", "3.0 MR 3"),
            "^3\.4\.", make_list("2010-03-09", "3.0 MR 4"),
            "^3\.5\.", make_list("2010-07-11", "3.0 MR 5"),
            "^3\.6\.", make_list("2011-02-11", "3.0 MR 6"),
            "^3\.7\.", make_list("2011-07-23", "3.0 MR 7"),
            "^4\.0\.", make_list("2012-03-12", "4.0"),
            "^4\.1\.", make_list("2012-09-11", "4.0 MR 1"),
            "^4\.2\.", make_list("2013-04-03", "4.0 MR 2"),
            "^4\.3\.", make_list("2014-06-30", "4.0 MR 3"),
            "^5\.0\.", make_list("2017-05-01", "5.0"),
            "^5\.2\.", make_list("2019-02-23", "5.0 MR 2"),
            "^5\.4\.", make_list("2020-08-17", "5.0 MR 4"),
            "^5\.6\.", make_list("2022-01-27", "5.0 MR 6"),
            "^6\.0\.", make_list("2022-10-18", "6.0"),
            "^6\.2\.", make_list("2022-10-18", "6.2")
          )
       ),
       "fortiweb", make_array(
          "Hardware", make_array(
            "FortiWeb-1000B", make_array('EOO',"2010-12-13", 'SED',"2014-12-13", 'EOS',"2015-12-13"),
            "FortiWeb-1000C", make_array('EOO',"2013-11-20", 'SED',"2017-11-20", 'EOS',"2018-11-20"),
            "FortiWeb-3000C", make_array('EOO',"2015-10-16", 'SED',"2019-10-16", 'EOS',"2020-10-16"),
            "FortiWeb-3000C-FSX", make_array('EOO',"2015-10-16", 'SED',"2019-10-16", 'EOS',"2020-10-16"),
            "FortiWeb-3000D", make_array('EOO',"2017-04-15", 'SED',"2021-04-15", 'EOS',"2022-04-15"),
            "FortiWeb-3000D-FSX", make_array('EOO',"2017-04-15", 'SED',"2021-04-15", 'EOS',"2022-04-15"),
#            "FortiWeb-3000D-FSX", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13"),
            "FortiWeb-3000D-FSX-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiWeb-4000C", make_array('EOO',"2013-07-25", 'SED',"2017-07-25", 'EOS',"2018-07-25"),
            "FortiWeb-4000D-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiWeb-400B", make_array('EOO',"2012-06-13", 'SED',"2016-06-13", 'EOS',"2017-06-13"),
            "FortiWeb-400C", make_array('EOO',"2016-07-16", 'SED',"2020-07-16", 'EOS',"2021-07-16"),
            "FortiWeb-400C-USG", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiWeb-VM", make_array('EOO',"2018-09-27", 'SED',"2022-09-27", 'EOS',"2023-09-27"),
            "FortiWeb-VM-USG", make_array('EOO',"2020-03-15", 'SED',"2024-03-15", 'EOS',"2025-03-15")
          ),
          "OS", make_array(
            "^3\.1\.", make_list("2012-04-20", "3.1"),
            "^3\.2\.", make_list("2012-06-04", "3.2"),
            "^3\.3\.", make_list("2012-09-03", "3.0 MR 3"),
            "^4\.0\.", make_list("2013-03-12", "4.0"),
            "^4\.1\.", make_list("2013-08-03", "4.0 MR 1"),
            "^4\.2\.", make_list("2014-02-01", "4.0 MR 2"),
            "^4\.3\.", make_list("2014-08-01", "4.0 MR 3"),
            "^4\.4\.", make_list("2015-06-22", "4.0 MR 4"),
            "^5\.1\.", make_list("2017-07-20", "5.0 MR 1"),
            "^5\.2\.", make_list("2017-11-01", "5.0 MR 2"),
            "^5\.3\.", make_list("2018-03-02", "5.0 MR 3"),
            "^5\.4\.", make_list("2018-08-14", "5.0 MR 4"),
            "^5\.5\.", make_list("2018-12-15", "5.0 MR 5"),
            "^5\.6\.", make_list("2019-09-26", "5.0 MR 6"),
            "^5\.7\.", make_list("2021-07-18", "5.0 MR 7"),
            "^5\.8\.", make_list("2021-10-27", "5.0 MR 8"),
            "^5\.9\.", make_list("2022-09-20", "5.0 MR 9"),
            "^6\.0\.", make_list("2022-11-23", "6.0"),
            "^6\.3\.", make_list("2024-07-21", "6.3"),
            "^6\.1\.", make_list("2023-09-27", "6.10"),
            "^6\.2\.", make_list("2024-03-30", "6.2")
          )
       ),
       "fortimail", make_array(
          "Hardware", make_array(
            "FortiMail 200D", make_array('EOO',"2016-12-14", 'SED',"2020-12-14", 'EOS',"2021-12-14"),
            "FortiMail 5002B", make_array('EOO',"2016-12-14", 'SED',"2020-12-14", 'EOS',"2021-12-14"),
            "FortiMail-100", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiMail-1000D", make_array('EOO',"2019-05-11", 'SED',"2023-05-11", 'EOS',"2024-05-11"),
            "FortiMail-1000D-USG", make_array('EOO',"2020-01-14", 'SED',"2024-01-14", 'EOS',"2025-01-14"),
            "FortiMail-100C", make_array('EOO',"2012-10-25", 'SED',"2016-10-25", 'EOS',"2017-10-25"),
            "FortiMail-100C-G", make_array('EOO',"2014-07-09", 'SED',"2018-07-09", 'EOS',"2019-07-09"),
            "FortiMail-2000", make_array('EOO',"2007-11-29", 'SED',"2011-11-29", 'EOS',"2013-11-29"),
            "FortiMail-2000A", make_array('EOO',"2011-04-21", 'SED',"2015-04-21", 'EOS',"2016-04-21"),
            "FortiMail-2000B", make_array('EOO',"2015-04-01", 'SED',"2019-04-01", 'EOS',"2020-04-01"),
            "FortiMail-2000B-G", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiMail-200D-G", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiMail-200E", make_array('EOO',"2019-05-09", 'SED',"2023-05-09", 'EOS',"2024-05-09"),
            "FortiMail-3000C", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2021-09-13"),
            "FortiMail-3000C-G", make_array('EOO',"2017-07-14", 'SED',"2021-07-14", 'EOS',"2022-07-14"),
            "FortiMail-3000D", make_array('EOO',"2017-01-30", 'SED',"2021-01-30", 'EOS',"2022-01-30"),
            "FortiMail-3000D-G", make_array('EOO',"2017-04-15", 'SED',"2021-04-15", 'EOS',"2022-04-15"),
            "FortiMail-400", make_array('EOO',"2011-11-17", 'SED',"2015-11-17", 'EOS',"2016-11-17"),
            "FortiMail-4000", make_array('EOO',"2007-03-01", 'SED',"2009-03-01", 'EOS',"2012-03-01"),
            "FortiMail-4000A", make_array('EOO',"2010-12-26", 'SED',"2014-12-26", 'EOS',"2015-12-26"),
            "FortiMail-400B", make_array('EOO',"2012-06-13", 'SED',"2016-06-13", 'EOS',"2017-06-13"),
            "FortiMail-400C", make_array('EOO',"2016-09-13", 'SED',"2020-09-13", 'EOS',"2022-09-13"),
            "FortiMail-400C-G", make_array('EOO',"2017-11-29", 'SED',"2021-11-29", 'EOS',"2022-11-29"),
            "FortiMail-400E", make_array('EOO',"2019-05-09", 'SED',"2023-05-09", 'EOS',"2024-05-09"),
            "FortiMail-5001A", make_array('EOO',"2013-07-25", 'SED',"2017-07-25", 'EOS',"2018-07-24"),
            "FortiMail-60D", make_array('EOO',"2019-09-04", 'SED',"2023-09-04", 'EOS',"2024-09-04"),
            "FortiMail-VM", make_array('EOO',"2018-09-29", 'SED',"2022-09-29", 'EOS',"2023-09-29")
          ),
          "OS", make_array(
            "^2\.8\.", make_list("2010-01-15", "2.8 MR 1"),
            "^3\.0\.", make_list("2010-08-03", "3.0"),
            "^3\.1\.", make_list("2010-11-01", "3.0 MR 1"),
            "^3\.2\.", make_list("2010-12-24", "3.0 MR 2"),
            "^3\.3\.", make_list("2011-04-18", "3.0 MR 3"),
            "^3\.4\.", make_list("2011-08-01", "3.0 MR 4"),
            "^3\.5\.", make_list("2012-05-07", "3.0 MR 5"),
            "^4\.0\.", make_list("2012-11-24", "4.0"),
            "^4\.1\.", make_list("2013-07-12", "4.0 MR 1"),
            "^4\.2\.", make_list("2014-03-11", "4.0 MR 2"),
            "^4\.3\.", make_list("2016-11-17", "4.0 MR 3"),
            "^5\.0\.", make_list("2017-08-28", "5.0"),
            "^5\.1\.", make_list("2018-06-19", "5.0 MR 1"),
            "^5\.2\.", make_list("2019-02-25", "5.0 MR 2"),
            "^5\.3\.", make_list("2020-05-30", "5.0 MR 3"),
            "^5\.4\.", make_list("2022-01-25", "5.0 MR 4"),
            "^6\.0\.", make_list("2022-11-29", "6.0"),
            "^6\.2\.", make_list("2024-02-09", "6.2")
          )
       )
     );

# Iterate through devices to determine appropriate EOL check.
foreach device (keys(eol))
{
  if (preg(string:model, pattern:device, icase:TRUE))
  {
    device_supported = TRUE;
    device_data = eol[device];
    break;
  }
}

# If device was not in the list, then exit with audit and we should add
# support for that device.
if (!device_supported) exit(0, model + " is not a supported device.");

# Iterate through Hardware Models to determine EOL date and finally check if
# date is earlier than today to flag as EOL.
foreach product (keys(device_data['Hardware']))
{
  if (model == product)
  {
    product_data = device_data['Hardware'][product];

    # Convert EOL date to unixtime for comparison.
    eoss = product_data['EOSS'];
    date = split(product_data['EOS'], sep:'-', keep:FALSE);
    date_unix = mktime(year: int(date[0]), mon: int(date[1]), mday: int(date[2]));

    if (date_unix < now)
    {
      eol_product = product;
      eol_product_date = product_data['EOS'];
      break;
    }
  }
}

# Iterate through Operating System versions to determine EOL date and finally check if
# date is earlier than today to flag as EOL.
foreach ver (keys(device_data["OS"]))
{
  if (version =~ ver)
  {
    ver_data = device_data["OS"][ver];

    # Convert EOL date to unixtime for comparison.
    date = split(ver_data[0], sep:'-', keep:FALSE);
    date_unix = mktime(year: int(date[0]), mon: int(date[1]), mday: int(date[2]));
    
    # Check if device is running Fortinet Operating System is out of date
    #  and is not exempted due to Device being Operating System Supported
    #    until End of Hardware/Device Support.  
    if ((date_unix < now) && (empty_or_null(eoss)) && (eoss >< ver))
    {
      eol_os_version = ver_data[1];
      eol_os_date = ver_data[0];
      break;
    }
  }
}


# Report if vulnerable.
report = '';
if ((eol_os_version && eol_os_date) || (eol_product && eol_product_date))
{
  port = 0;
  if (eol_os_version && eol_os_date)
  {
    report += '\n' + model + "'s operating system version " + eol_os_version + " has reached end of support on " + eol_os_date + '.\n';
    set_kb_item(name:'Host/OS/obsolete', value:TRUE);
    set_kb_item(name:'Host/OS/obsolete/text', value:report);
    register_unsupported_product(product_name:'Fortinet Fortios', cpe_class:CPE_CLASS_OS,
    version:version, cpe_base:"fortinet:fortios");
  }
  if (eol_product && eol_product_date)
  {
    report += '\n' + model + " has reached end of support on " + eol_product_date + '.\n';
    set_kb_item(name:'Host/HW/obsolete', value:TRUE);
    set_kb_item(name:'Host/HW/obsolete/text', value:report);
    register_unsupported_product(product_name:model, cpe_class:CPE_CLASS_OS,
    cpe_base:"fortinet:" + tolower(model));
  }

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_SUPPORTED, model, version);
