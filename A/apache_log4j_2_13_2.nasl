#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136424);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9488");
  script_xref(name:"IAVA", value:"2020-A-0196-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Apache Log4j < 2.13.2 Improper Certificate Verification");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by an improper certificate verification vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is < 2.13.2. It is, therefore, affected by 
an improper certificate validation vulnerability in the log4j SMTP appender. An 
attacker could leverage this vulnerability to perform a man-in-the-middle attack.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/LOG4J2-2819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.13.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:log4j");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

distros = make_list(
  'Host/RedHat/rpm-list',
  'Host/Gentoo/qpkg-list',
  'Host/SuSE/rpm-list',
  'Host/CentOS/rpm-list'
);

pkgs_list = make_array();

distro = '';

foreach pkgmgr (distros)
{
  pkgs = get_kb_item(pkgmgr);
  sep = '\n';
  if(!isnull(pkgs) && 'log4j' >< pkgs)
  {
    distro = pkgmgr;
    foreach pkg (split(pkgs,sep:sep,keep:FALSE))
    {
      match = pregmatch(pattern:"(?:\s|^)(?:apache-)?log4j2?-([0-9.-]+[0-9]+).*", string:pkg);
      if(!empty_or_null(match) && !empty_or_null(match[1]))
      {
        if("-" >< match[1])
          pkgs_list[pkg] = str_replace(string: match[1], find:'-', replace:'.');
        else pkgs_list[pkg] = match[1];
      }
    }
  }
}

flag = 0;
vulnerable_pkgs = '';

if(!empty_or_null(pkgs_list))
{
  foreach pkg (keys(pkgs_list))
  {
    ver = pkgs_list[pkg];
    if ((empty_or_null(ver)) || (ver !~ "(?!^.*\.\..*$)^[0-9][0-9.]+?$")) continue;
    if(ver_compare(ver:ver, fix:'2.13.2', strict:FALSE) < 0)
    {
      vulnerable_pkgs += '  ' + pkg + '\n';
      flag++;
    }
  }
}
else audit(AUDIT_NOT_INST, 'Apache Log4j');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(flag > 0)
{
  report = '\nThe following packages are associated with a vulnerable version of log4j : \n\n';
  report += vulnerable_pkgs;
  report += '\nFixed version : Log4j 2.13.2\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Apache Log4j');
