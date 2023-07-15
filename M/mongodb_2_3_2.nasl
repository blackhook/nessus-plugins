#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72334);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-6619");
  script_bugtraq_id(64687);

  script_name(english:"MongoDB < 2.3.2 BSON Object Length Handling Memory Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is a version prior to 2.3.2. 
It is, therefore, potentially affected by an information disclosure
vulnerability.  An error exists related to handling BSON (Binary
JavaScript Object Notation) objects having incorrect length that could
allow possible disclosure of information held in memory.");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/alerts#security-related");
  # https://groups.google.com/forum/#!searchin/mongodb-announce/SERVER-7769/mongodb-announce/3SkNJdemy84/ovLd_TclNh4J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cbacf08");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-7769");
  script_set_attribute(attribute:"see_also", value:"http://article.gmane.org/gmane.comp.security.oss.general/11822");
  script_set_attribute(attribute:"see_also", value:"http://blog.ptsecurity.com/2012/11/attacking-mongodb_26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB 2.3.2 / 2.4.0 or later.  Alternatively, use the
'--objcheck' command line switch to force object checking. 

Note that version 2.3.2 is a development version and is not recommended
for production use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6619");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Services/mongodb", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "MongoDB";

port = get_service(svc:"mongodb", exit_on_fail:TRUE);
version = get_kb_item_or_exit("mongodb/" + port + "/Version");
databases = get_kb_list('mongodb/' + port + '/Databases');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '2.3.2';

# Affected : < 2.3.2
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + ' / 2.4.0';
    if(databases)
      report += '\n  Databases         : ';
    first = TRUE;
    foreach database (databases)
    {
      if(!first)
        report += '                      ';
      report += database;
      collections = get_kb_item('mongodb/' + port + '/Collections/' + database);
      if(collections)
        report += ' - ' + collections;
      report  += '\n';
      first = FALSE;
    }

    report += '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
