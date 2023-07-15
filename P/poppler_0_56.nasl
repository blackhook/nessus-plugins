#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101167);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/05");

  script_cve_id("CVE-2017-9775", "CVE-2017-9776");
  script_bugtraq_id(99240, 99241);

  script_name(english:"Poppler < 0.56.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Poppler installed on the remote host is prior to
0.56.0. It is, therefore, affected by multiple vulnerabilities :

  - A stack-based overflow condition exists in the
    getColor() function in GfxState.cc due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted PDF document, to crash the
    process, resulting in a denial of service condition.
    (CVE-2017-9775)

  - An integer overflow condition exists in the combine()
    function in JBIG2Stream.cc due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted PDF document, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-9775)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.freedesktop.org/show_bug.cgi?id=101540");
  script_set_attribute(attribute:"see_also", value:"https://bugs.freedesktop.org/show_bug.cgi?id=101541");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Poppler version 0.56.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9776");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freedesktop:poppler");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

distros = make_list(
  'Host/AIX/lslpp',
  'Host/AmazonLinux/rpm-list',
  'Host/CentOS/rpm-list',
  'Host/Debian/dpkg-l',
  'Host/FreeBSD/pkg_info',
  'Host/Gentoo/qpkg-list',
  'Host/HP-UX/swlist',
  'Host/MacOSX/packages',
  'MacOSX/packages/homebrew',
  'Host/Mandrake/rpm-list',
  'Host/McAfeeLinux/rpm-list',
  'Host/OracleVM/rpm-list',
  'Host/RedHat/rpm-list',
  'Host/Slackware/packages',
  'Host/Solaris/showrev',
  'Host/Solaris11/pkg-list',
  'Host/SuSE/rpm-list'
);
  
pkgs_list = make_array();

distro = '';

foreach pkgmgr (distros)
{ 
  pkgs = get_kb_item(pkgmgr);
  if(pkgmgr=~"^MacOSX") sep = '|';
  else sep = '\n';
  if(!isnull(pkgs) && 'poppler' >< pkgs)
  {
    # so we know what distro we're looking at
    # helps for version compares
    distro = pkgmgr;
    foreach pkg (split(pkgs,sep:sep,keep:FALSE))
    {
      match = pregmatch(pattern:"(?:lib\d*|gir1.2-|\s|^)poppler\d*(?:-?(?:glib[^-]{0,2}|qt[^-]{0,2}|utils|dbg|dbgsym|debuginfo|private|devel|cpp[^-]{0,2}|gir[^-]+|dev|-0\.18|<|-\d|.x86-64)+)*(?:-|\s*)(\d+(?:\.\d+){1,4}(?:-[0-9]+)?)[^\n]*", string:pkg);
      if(!empty_or_null(match) && !empty_or_null(match[1]))
      {
        if('-' >< match[1])
          pkgs_list[pkg] = str_replace(string: match[1], find:'-', replace:'.');
        else pkgs_list[pkg] = match[1];
      }
    }
  }
}

paranoid_report=FALSE;
flag = 0;
vulnerable_pkgs = '';

if(!empty_or_null(pkgs_list))
{
  foreach pkg (keys(pkgs_list))
  {
    ver = pkgs_list[pkg];
    if ((empty_or_null(ver)) || (ver !~ "(?!^.*\.\..*$)^[0-9][0-9.]+?$")) continue;
    if(
      ('el7' >< pkg && ver_compare(ver:ver, fix:'0.26.5.16', strict:FALSE)<=0)                          ||
      ('el6' >< pkg && ver_compare(ver:ver, fix:'0.12.4.11', strict:FALSE)<=0)                          ||
      ('el5' >< pkg && ver_compare(ver:ver, fix:'0.5.4.19', strict:FALSE)<=0)                           ||
      # fc27 has fixed version, so <0     
      ('fc27' >< pkg && ver_compare(ver:ver, fix:'0.56.0.1', strict:FALSE)<0)                           ||
      ('fc26' >< pkg && ver_compare(ver:ver, fix:'0.52.0.2', strict:FALSE)<=0)                          ||
      ('fc25' >< pkg && ver_compare(ver:ver, fix:'0.45.0.3', strict:FALSE)<=0)                          ||
      ('fc24' >< pkg && ver_compare(ver:ver, fix:'0.41.0.4', strict:FALSE)<=0)                          ||
      ('fc23' >< pkg && ver_compare(ver:ver, fix:'0.34.0.4', strict:FALSE)<=0)                          ||
      ('fc22' >< pkg && ver_compare(ver:ver, fix:'0.30.0.4', strict:FALSE)<=0)                          ||
      ('ubuntu' >< pkg && ver_compare(ver:ver, fix:'0.48.0.2', minver:'0.45.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.48.0.2', minver:'0.45.0',strict:FALSE)))                 ||
      ('ubuntu' >< pkg && ver_compare(ver:ver, fix:'0.44.0.3', minver:'0.42.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.44.0.3', minver:'0.42.0',strict:FALSE)))                 ||
      ('ubuntu' >< pkg && ver_compare(ver:ver, fix:'0.41.0.0', minver:'0.25.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.41.0.0', minver:'0.25.0',strict:FALSE)))                 ||
      ('ubuntu' >< pkg && ver_compare(ver:ver, fix:'0.24.5.2', minver:'0.19.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.24.5.2', minver:'0.19.0',strict:FALSE)))                 ||
      ('ubuntu' >< pkg && ver_compare(ver:ver, fix:'0.18.4.1', strict:FALSE)<=0)                        ||
      ('SuSE' >< distro && ver_compare(ver:ver, fix:'0.43.0.1.3', minver:'0.27.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.43.0.1.3', minver:'0.27.0',strict:FALSE)))               ||
      ('SuSE' >< distro && ver_compare(ver:ver, fix:'0.26.5.6.1', minver:'0.25.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.26.5.6.1', minver:'0.25.0',strict:FALSE)))               ||
      ('SuSE' >< distro && ver_compare(ver:ver, fix:'0.24.4.12.1',strict:FALSE)<=0)                     ||
      ('Debian' >< distro && ver_compare(ver:ver, fix:'0.48.0.2', minver:'0.27.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.48.0.2', minver:'0.27.0',strict:FALSE)))                 ||
      ('Debian' >< distro && ver_compare(ver:ver, fix:'0.26.5.2', minver:'0.19.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.26.5.2', minver:'0.19.0',strict:FALSE)))                 ||
      ('Debian' >< distro && ver_compare(ver:ver, fix:'0.18.4.6',strict:FALSE)<=0)                      ||
      # Latest Mandrake has fixed version, so <0   
      ('Mandrake' >< distro && ver_compare(ver:ver, fix:'0.56.0.1', minver:'0.44.0',strict:FALSE)<0)    ||
      ('Mandrake' >< distro && ver_compare(ver:ver, fix:'0.43.0.2', minver:'0.37.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.43.0.2', minver:'0.37.0',strict:FALSE)))                 ||
      ('Mandrake' >< distro && ver_compare(ver:ver, fix:'0.36.0.2', minver:'0.25.0',strict:FALSE)<=0
        && !isnull(ver_compare(ver:ver, fix:'0.36.0.2', minver:'0.25.0',strict:FALSE)))                 ||
      ('Mandrake' >< distro && ver_compare(ver:ver, fix:'0.24.1.2', strict:FALSE)<=0)                   ||
      ('AmazonLinux' >< distro && ver_compare(ver:ver, fix:'0.26.5.17', strict:FALSE)<0)
      )
      {
        vulnerable_pkgs += '  ' + pkg + '\n';
        flag++;
        paranoid_report = TRUE;
      }
      # these distros don't appear to have backported versions
    else if(
      distro =~ "(Solaris|Gentoo|BSD|Slackware|HP-UX|AIX|McAfeeLinux|MacOSX)" && 
      ver_compare(ver:ver, fix:'0.56.0', strict:FALSE)<0
    )
    {
      vulnerable_pkgs += '  ' + pkg + '\n';
      flag++;
    }
  }
}
else audit(AUDIT_NOT_INST, 'poppler');

if(paranoid_report && report_paranoia < 2)
  exit(0, 'Potentially vulnerable packages were found, but the plugin will only report if \'Report paranoia\' is set to \'Paranoid\', due to potentially inaccurate backported versions.');

if(flag > 0)
{
  report = '\nThe following packages are associated with a vulnerable version of poppler : \n\n';
  report += vulnerable_pkgs;
  report += '\nFix : Upgrade poppler to a fixed release.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'poppler');
