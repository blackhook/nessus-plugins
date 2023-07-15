#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(120946);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2018-20481", "CVE-2018-20662");
  script_bugtraq_id(106321);

  script_name(english:"Poppler <= 0.72.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for an installation of poppler.");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Poppler installed on the remote host is prior or
equal to 0.72.0. It is, therefore, affected by multiple denial of
service (DoS) vulnerabilities in both XRef::getEntry in XRef.cc due
to a NULL pointer dereference and in PDFDoc::setup in PDFDoc.cc. A
local attacker can exploit this issue to cause an application that
uses poppler to render PDFs to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.freedesktop.org/poppler/poppler/issues/692");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.freedesktop.org/poppler/poppler/issues/706");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a patched version of Poppler once it is available.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freedesktop:poppler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

distros = make_list(
  "Host/AIX/lslpp",
  "Host/CentOS/rpm-list",
  "Host/Gentoo/qpkg-list",
  "Host/HP-UX/swlist",
  "Host/MacOSX/packages",
  "MacOSX/packages/homebrew",
  "Host/McAfeeLinux/rpm-list",
  "Host/RedHat/rpm-list",
  "Host/Slackware/packages",
  "Host/Solaris/showrev",
  "Host/Solaris11/pkg-list",
  "Host/SuSE/rpm-list"
);

pkgs_list = make_array();

distro = "";

foreach pkgmgr (distros)
{
  pkgs = get_kb_item(pkgmgr);
  if(pkgmgr=~"^MacOSX") sep = "|";
  else sep = '\n';
  if(!isnull(pkgs) && "poppler" >< pkgs)
  {
    # so we know what distro we're looking at
    # helps for version compares
    distro = pkgmgr;
    foreach pkg (split(pkgs,sep:sep,keep:FALSE))
    {
      match = pregmatch(pattern:"(?:lib\d*|gir1.2-|\s|^)poppler\d*(?:-?(?:glib[^-]{0,2}|qt[^-]{0,2}|utils|dbg|dbgsym|debuginfo|private|devel|cpp[^-]{0,2}|gir[^-]+|dev|-0\.18|<|-\d|.x86-64)+)*(?:-|\s*)(\d+(?:\.\d+){1,2}(?:-[0-9]+)?)[^\n]*", string:pkg);
      if(!empty_or_null(match) && !empty_or_null(match[1]))
      {
        if("-" >< match[1])
          pkgs_list[pkg] = str_replace(string: match[1], find:'-', replace:'.');
        else pkgs_list[pkg] = match[1];
      }
    }
  }
}

paranoid_report=FALSE;
flag = 0;
vulnerable_pkgs = "";

if(!empty_or_null(pkgs_list))
{
  foreach pkg (keys(pkgs_list))
  {
    ver = pkgs_list[pkg];
    if ((empty_or_null(ver)) || (ver !~ "(?!^.*\.\..*$)^[0-9][0-9.]+?$")) continue;
    if(
        ("el7" >< pkg && ver_compare(ver:ver, fix:"0.26.5.20", strict:FALSE)<=0) ||
        ("el6" >< pkg && ver_compare(ver:ver, fix:"0.12.4.12", strict:FALSE)<=0) ||
        ("el5" >< pkg && ver_compare(ver:ver, fix:"0.5.4.19", strict:FALSE)<=0) ||
        ("fc29" >< pkg && ver_compare(ver:ver, fix:"0.67.0.1", strict:FALSE)<=0) ||
        ("fc28" >< pkg && ver_compare(ver:ver, fix:"0.62.0.1", strict:FALSE)<=0) ||
        ("fc27" >< pkg && ver_compare(ver:ver, fix:"0.57.0.2", strict:FALSE)<=0)
      )
      {
        vulnerable_pkgs += '  ' + pkg + '\n';
        flag++;
        paranoid_report = TRUE;
      }
      # these distros don't appear to have backported versions
      # <= 0 since there's no fixed version out yet
    else if(
      distro =~ "(Solaris|Solaris11|Gentoo|BSD|Slackware|HP-UX|AIX|McAfeeLinux|MacOSX)" &&
      ver_compare(ver:ver, fix:"0.72.0", strict:FALSE) <= 0
    )
    {
      vulnerable_pkgs += '  ' + pkg + '\n';
      flag++;
    }
  }
}
else audit(AUDIT_NOT_INST, "poppler");

if(paranoid_report && report_paranoia < 2)
  exit(0, "Potentially vulnerable packages were found, but the plugin will only report if 'Report paranoia' is set to 'Paranoid', due to potentially inaccurate backported versions.");

if(flag > 0)
{
  report = '\nThe following packages are associated with a vulnerable version of poppler : \n\n';
  report += vulnerable_pkgs;
  report += '\nFix : Upgrade poppler to a fixed release.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "poppler");
