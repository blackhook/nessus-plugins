#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4124. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107024);
  script_version("3.5");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-12629", "CVE-2017-3163");
  script_xref(name:"DSA", value:"4124");
  script_xref(name:"IAVA", value:"2017-A-0319");

  script_name(english:"Debian DSA-4124-1 : lucene-solr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been found in Solr, a search server based on
Lucene, which could result in the execution of arbitrary code or path
traversal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/lucene-solr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/lucene-solr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/lucene-solr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4124"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lucene-solr packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 3.6.2+dfsg-5+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 3.6.2+dfsg-10+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lucene-solr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"liblucene3-contrib-java", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"liblucene3-java", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"liblucene3-java-doc", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolr-java", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"solr-common", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"solr-jetty", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"solr-tomcat", reference:"3.6.2+dfsg-5+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-contrib-java", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-java", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-java-doc", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsolr-java", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"solr-common", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"solr-jetty", reference:"3.6.2+dfsg-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"solr-tomcat", reference:"3.6.2+dfsg-10+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
