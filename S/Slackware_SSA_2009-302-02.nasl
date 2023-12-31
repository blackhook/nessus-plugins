#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-302-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42294);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3605", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_bugtraq_id(36703);
  script_xref(name:"SSA", value:"2009-302-02");

  script_name(english:"Slackware 12.0 / 12.1 / 12.2 / 13.0 / current : poppler (SSA:2009-302-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New poppler packages are available for Slackware 12.0, 12.1, 12.2,
13.0, and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.518348
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dba4f1ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler and / or poppler-data packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:poppler-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"12.0", pkgname:"poppler", pkgver:"0.6.2", pkgarch:"i486", pkgnum:"2_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"poppler", pkgver:"0.6.4", pkgarch:"i486", pkgnum:"2_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"poppler", pkgver:"0.8.5", pkgarch:"i486", pkgnum:"3_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"poppler", pkgver:"0.10.7", pkgarch:"i486", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"poppler", pkgver:"0.10.7", pkgarch:"x86_64", pkgnum:"2_slack13.0")) flag++;

if (slackware_check(osver:"current", pkgname:"poppler", pkgver:"0.12.1", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"poppler-data", pkgver:"0.3.0", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"poppler", pkgver:"0.12.1", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"poppler-data", pkgver:"0.3.0", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
