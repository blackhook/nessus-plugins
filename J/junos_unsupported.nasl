#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55933);
  script_version("1.51");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_xref(name:"IAVA", value:"0001-A-0544");

  script_name(english:"Juniper Junos Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The operating system running on the remote host is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
the Juniper Junos operating system running on the remote host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/eol/junos.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Juniper Junos that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('datetime.inc');

# Parse version
version = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item('Host/Juniper/model');

match = pregmatch(string:version, pattern:'^([0-9.]+(X[0-9]+)?)([^0-9]|$)');
if (isnull(match)) exit(1, 'Error parsing version: ' + version);
release = match[1];

eoe_date = NULL;
eos_date = NULL;

##############################
# End of Engineering (EOE)
#  Extended support contract needed beyond this date
eoe = make_array(
  "20.3",    "2022-09-29",
  "20.2",    "2023-06-30",
  "20.1",    "2022-03-27",
  "19.4",    "2022-12-26",
  "19.3",    "2022-09-26",
  "19.2",    "2022-06-26",
  "19.1",    "2022-03-27",
  "18.4",    "2021-12-22",
  "18.3",    "2021-09-26",
  "18.2",    "2021-06-29",
  "18.1",    "2021-03-28",
  "17.4",    "2020-12-21",
  "17.3",    "2020-08-25",
  "17.2",    "2020-06-06",
  "17.1",    "2020-03-03",
  "16.2",    "2019-11-29",
  "16.1",    "2019-07-28",
  "15.1X53", "2018-06-05",
  "15.1X49", "2020-12-31",
  "15.1",    "2022-06-30",
  "14.2",    "2017-11-05",
  "14.1X53", "2018-12-31",
  "14.1",    "2017-12-13",
  "13.3",    "2017-01-22",
  "13.2X52", "2016-12-31",
  "13.2X51", "2015-12-31",
  "13.2X50", "2014-06-28",
  "13.2",    "2015-08-29",
  "13.1X50", "2015-06-30",
  "13.1",    "2015-03-15",
  "12.3X54", "2018-01-18",
  "12.3X52", "2015-08-23",
  "12.3X51", "2015-03-15",
  "12.3X50", "2016-01-31",
  "12.3X48", "2020-06-30",
  "12.3",    "2016-01-31",
  "12.2X50", "2015-01-31",
  "12.2",    "2014-09-05",
  "12.1X49", "2014-04-19",
  "12.1X48", "2014-12-30",
  "12.1X47", "2016-08-18",
  "12.1X46", "2016-12-30",
  "12.1X45", "2014-07-17",
  "12.1X44", "2016-01-18",
  "12.1", "2014-03-28",
  "11.4", "2014-12-21",
  "11.3", "2012-07-15",
  "11.2", "2012-06-15",
  "11.1", "2011-11-15",
  "10.4", "2013-12-08",
  "10.3", "2011-08-03",
  "10.2", "2011-05-15",
  "10.1", "2010-11-15",
  "10.0", "2012-11-15",
  "9.6",  "2010-05-06",
  "9.5",  "2010-02-15",
  "9.4",  "2009-11-11",
  "9.3",  "2011-11-15",
  "9.2",  "2009-05-12",
  "9.1",  "2009-01-28",
  "9.0",  "2008-11-15",
  "8.5",  "2010-11-16",
  "8.4",  "2008-05-09",
  "8.3",  "2008-01-18",
  "8.2",  "2007-11-15",
  "8.1", "2009-11-06",
  "8.0", "2007-05-15",
  "7.6", "2007-02-15",
  "7.5", "2006-11-08",
  "7.4", "2006-08-15",
  "7.3", "2006-05-16",
  "7.2", "2006-02-14",
  "7.1", "2005-11-14",
  "7.0", "2005-08-15",
  "6.4", "2005-05-12",
  "6.3", "2005-02-15",
  "6.2", "2004-11-15",
  "6.1", "2004-08-15",
  "6.0", "2004-05-15",
  "5.7", "2004-02-15",
  "5.6", "2003-11-15",
  "5.5", "2003-08-15",
  "5.4", "2003-05-15",
  "5.3", "2003-02-15",
  "5.2", "2002-11-12",
  "5.1", "2002-08-12",
  "5.0", "2002-05-15",
  "4.4", "2002-02-12",
  "4.3", "2001-11-12",
  "4.2", "2001-08-13",
  "4.1", "2001-05-14",
  "4.0", "2001-02-12"
);


##############################
# End of Support (EOS)
#  Extended support end date
eos = make_array(
  "20.3",    "2023-03-29",
  "20.2",    "2023-12-30",
  "20.1",    "2022-09-27",
  "19.4",    "2023-06-26",
  "19.3",    "2023-03-26",
  "19.2",    "2022-12-26",
  "19.1",    "2022-09-27",
  "18.4",    "2022-06-22",
  "18.3",    "2022-03-26",
  "18.2",    "2021-12-29",
  "18.1",    "2021-09-28",
  "17.4",    "2021-06-21",
  "17.3",    "2021-02-25",
  "17.2",    "2020-12-06",
  "17.1",    "2020-09-03",
  "16.2",    "2020-05-29",
  "16.1",    "2020-01-28",
  "15.1X53", "2018-12-05",
  "15.1X49", "2020-05-01",
  "15.1",    "2024-06-30",
  "14.2",    "2018-05-05",
  "14.1X53", "2019-06-30",
  "14.1",    "2018-06-13",
  "13.3",    "2017-07-22",
  "13.2X52", "2017-06-30",
  "13.2X51", "2016-06-30",
  "13.2X50", "2014-12-28",
  "13.2",    "2016-02-29",
  "13.1X50", "2015-12-30",
  "13.1",    "2015-09-15",
  "12.3X54", "2018-07-18",
  "12.3X52", "2016-02-23",
  "12.3X51", "2015-09-15",
  "12.3X50", "2016-07-31",
  "12.3X48", "2022-06-30",
  "12.3",    "2016-07-31",
  "12.2X50", "2015-07-31",
  "12.2",    "2015-03-05",
  "12.1X49", "2014-10-19",
  "12.1X48", "2015-06-30",
  "12.1X47", "2017-02-18",
  "12.1X46", "2017-06-30",
  "12.1X45", "2015-01-17",
  "12.1X44", "2016-07-18",
  "12.1", "2014-09-28",
  "11.4", "2015-06-21",
  "11.3", "2013-03-15",
  "11.2", "2013-02-15",
  "11.1", "2012-05-15",
  "10.4", "2014-06-08",
  "10.3", "2011-12-21",
  "10.2", "2011-11-15",
  "10.1", "2011-05-15",
  "10.0", "2013-05-15",
  "9.6", "2010-11-06",
  "9.5", "2010-08-15",
  "9.4", "2010-05-11",
  "9.3", "2012-05-15",
  "9.2", "2009-11-12",
  "9.1", "2009-07-28",
  "9.0", "2009-05-15",
  "8.5", "2011-05-16",
  "8.4", "2008-11-09",
  "8.3", "2008-07-18",
  "8.2", "2008-05-15",
  "8.1", "2010-05-06",
  "8.0", "2007-11-15",
  "7.6", "2007-08-15",
  "7.5", "2007-05-08",
  "7.4", "2007-02-15",
  "7.3", "2006-11-16",
  "7.2", "2006-08-14",
  "7.1", "2006-05-14",
  "7.0", "2006-02-15",
  "6.4", "2005-11-12",
  "6.3", "2005-08-15",
  "6.2", "2005-05-15",
  "6.1", "2005-02-15",
  "6.0", "2004-11-15",
  "5.7", "2004-08-15",
  "5.6", "2004-05-15",
  "5.5", "2004-02-15",
  "5.4", "2003-11-15",
  "5.3", "2003-08-15",
  "5.2", "2003-05-15",
  "5.1", "2003-02-15",
  "5.0", "2002-11-15",
  "4.4", "2002-08-15",
  "4.3", "2002-05-15",
  "4.2", "2002-02-15",
  "4.1", "2001-11-15",
  "4.0", "2001-08-15"
);

#Determine EOE Date
#  12.3 extended EOE/EOS
if (release == "12.3" )
{
  if (model)
  {
    if ( model =~ "^EX-?2200(-C)?" )
    {
      eoe_date = "2022-06-30";
      eos_date = "2024-06-30";
    }
    else if ( model =~ "^EX-?[0-9]+" )
    {
      eoe_date = "2019-01-31";
      eos_date = "2019-07-31";
    }
    else if ( model =~ "^QFX-?[0-9]+" )
    {
      eoe_date = "2017-01-31";
      eos_date = "2017-07-31";
    }
    else if ( model =~ "^EX8200")
    {
      eoe_date = "2019-05-01";
      eos_date = "2021-05-01";
    }
  }
}
#  12.3X48 extended EOE/EOS
if (release == "12.3X48" )
{
  if (model)
  {
    if ( model =~ "^SRX-?(14|34|36)00" )
    {
      eoe_date = "2020-12-01";
      eos_date = "2022-12-01";
    }
  }
}

#  12.3X50 extended EOE/EOS
if (release == "12.3X50" )
{
  if (model)
  {
    if (
        model =~ "^EX-?[0-9]+" ||
        model =~ "^QFX-?[0-9]+"
       )
    {
      eoe_date = "2017-01-31";
      eos_date = "2017-07-31";
    }
  }
}

#  12.1X46EOE/EOS
if (release == "12.1X46")
{
  if (model)
  {
    if (model =~ "^J[0-9]+")
    {
      eoe_date = '2018-07-31';
      eos_date = '2018-07-31';
    }
    else if (
      model == 'SRX100B'      ||
      model == 'SRX100H'      ||
      model == 'SRX110H-VA'   ||
      model == 'SRX110H-VB'   ||
      model == 'SRX210BE'     ||
      model == 'SRX210HE'     ||
      model == 'SRX210HE-POE' ||
      model == 'SRX220H'      ||
      model == 'SRX220H-POE'  ||
      model == 'SRX240B'      ||
      model == 'SRX240B2'     ||
      model == 'SRX240H'      ||
      model == 'SRX240H-POE'  ||
      model == 'SRX240H-DC'   ||
      model == 'LN1000-V'     ||
      model == 'LN1000-CC'
    )
    {
      eoe_date = '2019-05-10';
      eos_date = '2019-05-10';
    }
  }
}

#  14.1R4 extended EOE/EOS
if (release == "14.1R4")
{
  if (model =~ "^MX-?[0-9]")
  {
    eoe_date = "2018-12-13";
    eos_date = "2019-06-13";
  }
}

#  14.1X53 extended EOE/EOS
if (release == '14.1X53')
{
  if (version =~ "D47")
  {
    eoe_date = '2019-06-30';
    eos_date = '2019-12-31';
  }
}

#  14.1X53-D51 extended EOE/EOS
if (release == '14.1X53')
{
  if (version =~ "D51")
  {
    eoe_date = '2020-06-30';
    eos_date = '2020-12-31';
  }
}

#  14.1X53-D130 extended EOE\EOS
if (release == '14.1X53')
{
  if (version =~ "D130")
  {
    eoe_date = '2019-08-30';
    eos_date = '2023-12-31';
  }
}

#  15.1 extended EOE/EOS
if (release == '15.1')
{
  if (model)
  {
    if (
        model =~ "^M[0-9]+"   ||
        model =~ "^EX2200"    ||
        model =~ "^EX3200"    ||
        model =~ "^EX3300"    ||
        model =~ "^EX4500"    ||
        model =~ "^EX4550"    ||
        model =~ "^EX6200"    ||
        model =~ "^EX6210"    ||
        model =~ "^EX8200"    ||
        model == "EX9200-4QS" ||
        model =~ "^QFX3500"   ||
        model =~ "^QFX3600"   ||
        model == "T640"       ||
        model == "T1600"      ||
        model =~ "^EX4200-(24|48)(PX|[FT])"
        )
    {
      eoe_date = '2019-05-01';
      eos_date = '2021-05-01';
    }
  }
}

#  15.1X53 extended EOE/EOS
if (release == '15.1X53')
{
  if (model)
  {
    if (
        model =~ "^EX2300"    ||
        model =~ "^EX3400"
        )
    {
      eoe_date = '2018-12-05';
      eos_date = '2019-05-05';
    }
  }
}

# 16.1R7 extended EOE/EOS
if (release == '16.1')
{
    if (version =~ "16.1R7")
    {
      eoe_date = '2020-07-28';
      eos_date = '2021-01-28';
    }
}

# 16.2 extended EOS ONLY
# EOE remians the same according to https://support.juniper.net/support/eol/software/junos/#8
if (release == '16.2')
{
    if (model)
    {
      if (
          model =~ "^T4000"    ||
          model =~ "^TX3D"     ||
          model =~ "^MX240"     ||
          model =~ "^MX480"     ||
          model =~ "^MX960"     ||
          model =~ "^PTX3000"   ||
          model =~ "^PTX5000"
         )
      {
        eoe_date = '2019-11-29';
        eos_date = '2021-05-01';
      }
     }
}

# 17.3R3 extended EOE/EOS
if (release == '17.3')
{
    if (version =~ "17.3R3")
    {
       eoe_date = '2021-08-25';
       eos_date = '2022-02-25';
    }
}

# 17.4R2 and later extended EOE/EOS
if (release == '17.4')
{
      if (version =~ "^17.4R([2-9]|[1-9][0-9])")
      {
        eoe_date = '2021-08-25';
        eos_date = '2022-02-25';
      }
}

if (model)
{
  found = FALSE;

  # Handle model-specific exceptions found here
  # https://support.juniper.net/support/eol/hardware/ex_series/

  exc_str = "EX2200-24P-4G, EX2200-24P-4G-TAA, EX2200-24T-4G, EX2200-24T-4G-DC, EX2200-24T-4G-TAA, EX2200-48P-4G, EX2200-48P-4G-TAA, EX2200-48T-4G, EX2200-48T-4G-TAA, EX2200-BOX-10, EX2200-C-12P-2G, EX2200-C-12P2G-TAA, EX2200-C-12T-2G, EX3300-24P, EX3300-24P-TAA, EX3300-24T, EX3300-24T-DC, EX3300-24T-DC-TAA, EX3300-24T-TAA, EX3300-48P, EX3300-48P-TAA, EX3300-48T, EX3300-48T-BF, EX3300-48T-BF-TAA, EX3300-48T-TAA, EX-RPS-CBL, EX-RPS-PWR, EX-RPS-PWR-930-AC, EX-RPS-PWR-BLNK, EX4200-24F, EX4200-24F-AFL, EX4200-24F-DC, EX4200-24F-DC-TAA, EX4200-24F-S, EX4200-24F-TAA, EX4200-24PX, EX4200-24PX-AFL, EX4200-24PX-TAA, EX4200-24T, EX4200-24T-AFL, EX4200-24T-DC, EX4200-24T-TAA, EX4200-48PX, EX4200-48PX-AFL, EX4200-48PX-TAA, EX4200-48T, EX4200-48T-AFL, EX4200-48T-DC, EX4200-48T-S, EX4200-48T-TAA, EX4200-BOX-10, EX4200-FANTRAY, EX4200-PWR-BLNK, EX-PWR-190-DC, EX-PWR-320-AC, EX-PWR3-930-AC, EX-UM-2X4SFP, EX-UM-2X4SFP-M, EX-UM-2XFP, EX-UM-4SFP, EX-CBL-VCP-1M, EX-CBL-VCP-3M, EX-CBL-VCP-50CM, EX-CBL-VCP-5M, EX-CBL-VCP-LK, EX-XFP-10GE-ER, EX-XFP-10GE-LR, EX-XFP-10GE-SR, EX-XFP-10GE-ZR, EX4500-4PST-RMK, EX4550-AFL, EX4550-32F-AFI, EX4550-32F-AFO, EX4550-32F-DC-AFI, EX4550-32F-DC-AFO, EX4550-32F-S, EX4550-32T-AFI, EX4550-32T-AFO, EX4550-32T-DC-AFI, EX4550-32T-DC-AFO, EX4550-EM-2QSFP, EX4550-EM-8XSFP, EX4550-EM-8XT, EX4550F-AFI-TAA, EX4550F-AFO-TAA, EX4550-FANMODULE-AFI, EX4550-FANMODULE-AFO, EX4550F-DC-AFI-TAA, EX4550F-DC-AFO-TAA, EX4550T-AFI-TAA, EX4550T-AFO-TAA, EX4550T-DC-AFI-TAA, EX4550T-DC-AFO-TAA, EX4550-VC1-128G";
  exc_list = split(exc_str, sep:', ', keep:FALSE);

  foreach exc (exc_list)
    if (tolower(exc) == tolower(model))
      found = TRUE;

  if (found)
  {
    eoe_date = "2022-06-30";
    eos_date = "2024-06-30";
  }

  if (!found)
  {
    exc_str = "EX-SFP-1FE-FX-ET, EX-SFP-1FE-LH";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2021-09-19";
      eos_date = "2023-09-19";
    }
  }

  if (!found)
  {
    exc_str = "EX9200-SF, EX9204-BASE-AC, EX9204-BASE-AC-T, EX9204-RED-AC-T, EX9204-REDUND-AC, EX9204-REDUND-DC, EX9208-BASE-AC, EX9208-BASE-AC-T, EX9208-RED-AC-T, EX9208-REDUND-AC, EX9208-REDUND-DC, EX9214-BASE3-AC, EX9214-BASE3-AC-T, EX9214-RED3-AC-T, EX9214-REDUND3-AC, EX9214-REDUND3-DC";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2022-01-31";
      eos_date = "2024-01-31";
    }
  }


  if (!found)
  {
    exc_str = "EX8200-2XS-40P, EX8200-2XS-40T, EX8200-40XS, EX8200-40XS-ES, EX8200-48PL, EX8200-48TL, EX8200-2XS-40P-TAA, EX8200-2XS-40T-TAA, EX8200-40XS-TAA, EX8200-48PL-TAA, EX8200-48TL-TAA";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2019-05-01";
      eos_date = "2021-05-01";
    }
  }

  if (!found)
  {
    exc_str = "EX8200";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2020-01-01";
      eos_date = "2022-01-01";
    }
  }

  if (!found)
  {
    exc_str = "EX3200-24P, EX3200-24P-TAA, EX3200-24T, EX3200-24T-DC, EX3200-24T-TAA, EX3200-48P, EX3200-48P-TAA, EX3200-48T, EX3200-48T-DC, EX3200-48T-TAA, EX3200-FANTRAY";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2018-11-30";
      eos_date = "2019-08-31";
    }
  }

  if (!found)
  {
    exc_str = "EX-PWR-600-AC";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2017-09-30";
      eos_date = "2018-09-30";
    }
  }

  if (!found)
  {
    exc_str = "EX4500-40F-BF-C, EX4500-40F-DC-C, EX4500-40F-FB-C, EX4500-LB";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2017-12-31";
      eos_date = "2018-12-31";
    }
  }

  if (!found)
  {
    exc_str = "EX4200-48P, EX4200-24P";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2017-06-30";
      eos_date = "2018-06-30";
    }
  }

  if (!found)
  {
    exc_str = "EX2500-24F-BF, EX2500-24F-FB";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2016-11-30";
      eos_date = "2017-11-30";
    }
  }

  if (!found)
  {
    exc_str = "EX4500-40F-FB, EX4500-40F-BF";
    exc_list = split(exc_str, sep:', ', keep:FALSE);

    foreach exc (exc_list)
      if (tolower(exc) == tolower(model))
        found = TRUE;

    if (found)
    {
      eoe_date = "2015-04-30";
      eos_date = "2016-01-31";
    }
  }


  ##
  #  Nothing matched specific model checks
  #  Attempt to match 'Remaining <model> SKUs' listings
  #  found here:  https://support.juniper.net/support/eol/hardware/ex_series/
  ##

  if (!found)
  {
    if ("ex8200" >< tolower(model))
      found = TRUE;

    if (found)
    {
      eoe_date = "2020-01-01";
      eos_date = "2022-01-01";
    }
  }

  if (!found)
  {
    if ("ex4500" >< tolower(model) ||
        "ex6200" >< tolower(model) ||
	"ex9200" >< tolower(model))
	found = TRUE;

    if (found)
    {
      eoe_date = "2019-05-01";
      eos_date = "2021-05-01";
    }
  }

}

if (!eoe_date)
  eoe_date = eoe[release];

# Determine EOS Date
if (!eos_date)
  eos_date = eos[release];

# Check the EOE date
if (eoe_date)
{
  date = split(eoe_date, sep:"-");
  if (unixtime() < mktime(year:date[0], mon:date[1], mday:date[2]))
  {
    if(model)
      exit(0, "JunOS "+version+" is still supported on model "+model+".");
    else
      exit(0, "JunOS "+version+" is still supported.");
  }
}

#Check EOS date
if (eos_date)
{
  set_kb_item(
    name:"Host/Juniper/JUNOS/extended_support",
    value:"Junos "+release+" extended support ends on " + eos_date + "."
    );
}
# Couldn't identify either the EOE or EOS
if (!eoe_date && release !~ "^[0-3]\.")
  exit(0, "The EOE date could not be determined.");

# Anything left is affected
if (!eos_date)
  eos_date = "Unknown";
if (!eoe_date)
  eoe_date = "Unknown";
if (!model)
  model = 'Unknown';

set_kb_item(name:"Host/Juniper/JUNOS/unsupported", value:TRUE);

register_unsupported_product(product_name:'Juniper Junos', cpe_class:CPE_CLASS_OS,
                             version:tolower(release), cpe_base:"juniper:junos");

report =
  '\n  Installed version            : ' + version  +
  '\n  Junos release                : ' + release  +
  '\n  Model                        : ' + model  +
  '\n  End of life date             : ' + eoe_date +
  '\n  End of extended support date : ' + eos_date +
  '\n  EOE and EOS URL              : http://www.juniper.net/support/eol/junos.html' +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
