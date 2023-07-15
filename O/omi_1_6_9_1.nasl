##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162395);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-29149");
  script_xref(name:"IAVA", value:"2022-A-0248");

  script_name(english:"Microsoft Open Management Infrastructure (OMI) package < 1.6.9-1 Privilege Escalation Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Open Management Infrastructure (OMI) package installed on the remote host is prior to
1.6.9-1. It is, therefore, affected by a privilege escalation vulnerability. An unauthenticated, remote attacker can
exploit this, to gain privileged access to the system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29149");
  script_set_attribute(attribute:"see_also", value:"https://github.com/microsoft/omi/releases");
  script_set_attribute(attribute:"solution", value:
"Update to version 1.6.9-1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:open_management_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('rpm.inc');
include('debian_package.inc');
include('ubuntu.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var rpm_flag = 0;
# CentOS Linux
if (rpm_check(release:'CentOS-7', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'CentOS-8', reference:'omi-1.6.9-1')) rpm_flag++;
# Red Hat Enterprise Linux
if (rpm_check(release:'RHEL7', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'RHEL8', reference:'omi-1.6.9-1')) rpm_flag++;
# Oracle Enterprise Linux
if (rpm_check(release:'EL7', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'EL8', reference:'omi-1.6.9-1')) rpm_flag++;
# Amazon Linux
if (rpm_check(release:'ALA', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'AL2', reference:'omi-1.6.9-1')) rpm_flag++;
# Fedora Core
if (rpm_check(release:'FC33', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'FC34', reference:'omi-1.6.9-1')) rpm_flag++;
# NewStart CGSL
if (rpm_check(release:'ZTE CGSL MAIN 4.06', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'ZTE CGSL MAIN 5.04', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'ZTE CGSL MAIN 6.02', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'ZTE CGSL CORE 5.04', reference:'omi-1.6.9-1')) rpm_flag++;
# Scientifix Linux
if (rpm_check(release:'SL6', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'SL7', reference:'omi-1.6.9-1')) rpm_flag++;
# OpenSUSE
if (rpm_check(release:'SUSE15.2', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'SUSE15.3', reference:'omi-1.6.9-1')) rpm_flag++;
# Virtuozzo
if (rpm_check(release:'Virtuozzo-6', reference:'omi-1.6.9-1')) rpm_flag++;
if (rpm_check(release:'Virtuozzo-7', reference:'omi-1.6.9-1')) rpm_flag++;

var deb_flag = 0;
# Debian Linux
if (deb_check(release:'8.0', prefix:'omi', reference:'1.6.9-1')) deb_flag++;
if (deb_check(release:'9.0', prefix:'omi', reference:'1.6.9-1')) deb_flag++;
if (deb_check(release:'10.0', prefix:'omi', reference:'1.6.9-1')) deb_flag++;
if (deb_check(release:'11.0', prefix:'omi', reference:'1.6.9-1')) deb_flag++;

var ubuntu_flag = 0;
# Ubuntu Linux
if (ubuntu_check(osver:'14.04', pkgname:'omi', pkgver:'1.6.9-1')) ubuntu_flag++;
if (ubuntu_check(osver:'16.04', pkgname:'omi', pkgver:'1.6.9-1')) ubuntu_flag++;
if (ubuntu_check(osver:'18.04', pkgname:'omi', pkgver:'1.6.9-1')) ubuntu_flag++;
if (ubuntu_check(osver:'20.04', pkgname:'omi', pkgver:'1.6.9-1')) ubuntu_flag++;
if (ubuntu_check(osver:'21.04', pkgname:'omi', pkgver:'1.6.9-1')) ubuntu_flag++;

if (rpm_flag || deb_flag || ubuntu_flag)
{
  var extra;

  if (rpm_flag)
    extra = rpm_report_get();
  else if (deb_flag)
    extra = deb_report_get();
  else if (ubuntu_flag)
    extra = ubuntu_report_get();

  security_report_v4(
    port: 0,
    severity: SECURITY_WARNING,
    extra: extra
  );
  exit(0);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
