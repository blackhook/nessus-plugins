#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:087. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82340);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-2027");
  script_xref(name:"MDVSA", value:"2015:087");

  script_name(english:"Mandriva Linux Security Advisory : egroupware (MDVSA-2015:087)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated egroupware packages fix security vulnerabilities :

eGroupware prior to 1.8.006.20140217 is vulnerable to remote file
deletion and possible remote code execution due to user input being
passed to PHP's unserialize() method (CVE-2014-2027).

eGroupWare before 1.8.007 allows logged in users with administrative
priviledges to remotely execute arbitrary commands on the server. It
is also vulnerable to a cross site request forgery vulnerability that
allows creating new administrative users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0116.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0221.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-bookmarks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-developer_tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-egw-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-emailadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-felamimail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-filemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-gallery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-importexport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-infolog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-news_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-notifications");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-phpbrain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-phpsysinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-polls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-projectmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-registration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-sambaadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-sitemgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-syncml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-timesheet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-tracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:egroupware-wiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-bookmarks-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-calendar-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-developer_tools-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-egw-pear-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-emailadmin-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-felamimail-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-filemanager-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-gallery-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-importexport-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-infolog-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-manual-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-news_admin-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-notifications-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-phpbrain-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-phpsysinfo-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-polls-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-projectmanager-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-registration-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-sambaadmin-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-sitemgr-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-syncml-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-timesheet-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-tracker-1.8.007.20140506-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"egroupware-wiki-1.8.007.20140506-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
