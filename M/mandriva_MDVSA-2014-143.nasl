#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:143. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76924);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-4954", "CVE-2014-4955", "CVE-2014-4986", "CVE-2014-4987");
  script_bugtraq_id(68798, 68799, 68803, 68804);
  script_xref(name:"MDVSA", value:"2014:143");

  script_name(english:"Mandriva Linux Security Advisory : phpmyadmin (MDVSA-2014:143)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in
phpmyadmin :

Cross-site scripting (XSS) vulnerability in the
PMA_getHtmlForActionLinks function in libraries/structure.lib.php in
phpMyAdmin 4.2.x before 4.2.6 allows remote authenticated users to
inject arbitrary web script or HTML via a crafted table comment that
is improperly handled during construction of a database structure page
(CVE-2014-4954).

Cross-site scripting (XSS) vulnerability in the PMA_TRI_getRowForList
function in libraries/rte/rte_list.lib.php in phpMyAdmin 4.0.x before
4.0.10.1, 4.1.x before 4.1.14.2, and 4.2.x before 4.2.6 allows remote
authenticated users to inject arbitrary web script or HTML via a
crafted trigger name that is improperly handled on the database
triggers page (CVE-2014-4955).

Multiple cross-site scripting (XSS) vulnerabilities in js/functions.js
in phpMyAdmin 4.0.x before 4.0.10.1, 4.1.x before 4.1.14.2, and 4.2.x
before 4.2.6 allow remote authenticated users to inject arbitrary web
script or HTML via a crafted (1) table name or (2) column name that is
improperly handled during construction of an AJAX confirmation message
(CVE-2014-4986).

server_user_groups.php in phpMyAdmin 4.1.x before 4.1.14.2 and 4.2.x
before 4.2.6 allows remote authenticated users to bypass intended
access restrictions and read the MySQL user list via a viewUsers
request (CVE-2014-4987).

This upgrade provides the latest phpmyadmin version (4.2.6) to address
these vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/p/phpmyadmin/news/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-4.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-6.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-7.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpmyadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK-MBS1", reference:"phpmyadmin-4.2.6-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
