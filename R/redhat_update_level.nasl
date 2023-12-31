#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
 script_id(14657);
 script_version("1.41");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

 script_name(english:"Red Hat Update Level");
 script_summary(english:"Checks for RedHat update level.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat server is out-of-date.");
 script_set_attribute(attribute:"description", value:
"The remote Red Hat server is missing the latest bugfix update package.
As a result, it is likely to contain multiple security
vulnerabilities.");
 script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3078");
 script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata");
 script_set_attribute(attribute:"solution", value:
"Apply the latest update.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/03");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:linux");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/local_checks_enabled", "Host/RedHat/release");

 exit(0);
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var lastupdate;

lastupdate[8] = 4;
lastupdate[7] = 9;
lastupdate[6] = 10;
lastupdate[5] = 11;
lastupdate[4] = 9;
lastupdate[3] = 9;
lastupdate[2] = 7;

var buf = get_kb_item("Host/RedHat/release");
if (isnull(buf) || "Red Hat" >!< buf) audit(AUDIT_OS_NOT, "Red Hat");
if ("CoreOS" >< buf) audit(AUDIT_OS_NOT, "Red Hat");

var match = pregmatch(pattern:"Red Hat Enterprise Linux.*release ([0-9]+)(\.([0-9]+))?", string:buf);
if (isnull(match)) exit(1, "Failed to determine the Red Hat release.");

var release = int(match[1]);
var release_ui = release;

var updatelevel = NULL;
if (!isnull(match[2])) updatelevel = int(match[3]);

if (release == 2 && updatelevel == 1)
{
  release_ui = "2.1";
  updatelevel = NULL;
}

if (isnull(updatelevel))
{
  match = pregmatch(pattern:"Update ([0-9]+)", string:buf);
  if (!isnull(match)) updatelevel = int(match[1]);
}
if (isnull(updatelevel)) exit(1, "Failed to determine the Red Hat update level for release "+release_ui+".");

if (isnull(lastupdate[release])) exit(1, "Unknown update level for release '"+release_ui+"'.");

if (updatelevel < lastupdate[release])
{
  if (report_verbosity > 0)
  {
    var report;

    if (release_ui != '2.1')
    {
      report =
        '\n  Installed version : ' + release + '.' + updatelevel +
        '\n  Latest version    : ' + release + '.' + lastupdate[release] +
        '\n';
    }
    else
    {
      report =
        '\n  Installed version : ' + release_ui + ' Update ' + updatelevel +
        '\n  Latest version    : ' + release_ui + ' Update ' + lastupdate[release] +
        '\n';
    }

    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else
{
  if (release_ui != '2.1') exit(0, "The host is running Red Hat "+release_ui+"."+updatelevel+", which is the latest update release for Red Hat "+release_ui+".x.");
  else exit(0, "The host is running Red Hat "+release_ui+" Update "+updatelevel+", which is the latest update release for Red Hat "+release_ui+".");
}
