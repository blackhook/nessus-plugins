#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-209-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22152);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-3747");
  script_xref(name:"SSA", value:"2006-209-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 8.1 / 9.0 / 9.1 / current : Apache httpd (SSA:2006-209-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix a security issue with mod_rewrite."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.610131
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdfa00c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache and / or mod_ssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"8.1", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;
if (slackware_check(osver:"9.0", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;
if (slackware_check(osver:"10.0", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"apache", pkgver:"1.3.37", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mod_ssl", pkgver:"2.8.28_1.3.37", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
