#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_44278. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86115);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2015-2132");
  script_xref(name:"HP", value:"emr_na-c04735247");

  script_name(english:"HP-UX PHKL_44278 : s700_800 11.31 vm cumulative patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 vm cumulative patch : 

A potential security vulnerability have been identified with HP-UX
programs using the execve(2) system call. The vulnerability could be
exploited locally to create an elevation of privilege. References:
CVE-2015-2132 (SSRT102037)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04735247
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95625e46"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_44278 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2132");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include('hpux.inc');


if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/HP-UX/version')) audit(AUDIT_OS_NOT, 'HP-UX');
if (!get_kb_item('Host/HP-UX/swlist')) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:'11.31'))
{
  exit(0, 'The host is not affected since PHKL_44278 applies to a different OS release.');
}

var patches = make_list('PHKL_44230', 'PHKL_44278', 'PHKL_44298', 'PHKL_44417', 'PHKL_44461', 'PHKL_44464', 'PHKL_44500', 'PHKL_44510', 'PHKL_44565', 'PHKL_44702', 'PHKL_44730', 'PHKL_44767', 'PHKL_44801', 'PHKL_44816', 'PHKL_44853');

var patch;
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, 'The host is not affected because patch '+patch+' is installed.');
  }
}


var flag = 0;
if (hpux_check_patch(app:'OS-Core.ADMN-ENG-A-MAN', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'OS-Core.CORE-ENG-A-MAN', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'OS-Core.CORE2-KRN', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'OS-Core.KERN-ENG-A-MAN', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'ProgSupport.C-INC', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'ProgSupport.C2-INC', version:'B.11.31')) flag++;
if (hpux_check_patch(app:'ProgSupport.PAUX-ENG-A-MAN', version:'B.11.31')) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
