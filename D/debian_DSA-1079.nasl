#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1079. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22621);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
  script_bugtraq_id(16850, 17780);
  script_xref(name:"CERT", value:"602457");
  script_xref(name:"DSA", value:"1079");

  script_name(english:"Debian DSA-1079-1 : mysql-dfsg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in MySQL, a popular SQL
database. The Common Vulnerabilities and Exposures Project identifies
the following problems :

  - CVE-2006-0903
    Improper handling of SQL queries containing the NULL
    character allows local users to bypass logging
    mechanisms.

  - CVE-2006-1516
    Usernames without a trailing null byte allow remote
    attackers to read portions of memory.

  - CVE-2006-1517
    A request with an incorrect packet length allows remote
    attackers to obtain sensitive information.

  - CVE-2006-1518
    Specially crafted request packets with invalid length
    values allow the execution of arbitrary code.

The following vulnerability matrix shows which version of MySQL in
which distribution has this problem fixed :

                   woody            sarge            sid              
  mysql            3.23.49-8.15     n/a              n/a              
  mysql-dfsg       n/a              4.0.24-10sarge2  n/a              
  mysql-dfsg-4.1   n/a              4.1.11a-4sarge3  n/a              
  mysql-dfsg-5.0   n/a              n/a              5.0.21-3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=366044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=366049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=366163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1079"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the mysql packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.1", prefix:"libmysqlclient12", reference:"4.0.24-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libmysqlclient12-dev", reference:"4.0.24-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-client", reference:"4.0.24-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-common", reference:"4.0.24-10sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"mysql-server", reference:"4.0.24-10sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
