#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4194. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109589);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-1308");
  script_xref(name:"DSA", value:"4194");

  script_name(english:"Debian DSA-4194-1 : lucene-solr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An XML external entity expansion vulnerability was discovered in the
DataImportHandler of Solr, a search server based on Lucene, which
could result in information disclosure."
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
    value:"https://www.debian.org/security/2018/dsa-4194"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lucene-solr packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 3.6.2+dfsg-5+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 3.6.2+dfsg-10+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lucene-solr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"liblucene3-contrib-java", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"liblucene3-java", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"liblucene3-java-doc", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsolr-java", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"solr-common", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"solr-jetty", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"solr-tomcat", reference:"3.6.2+dfsg-5+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-contrib-java", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-java", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"liblucene3-java-doc", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsolr-java", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"solr-common", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"solr-jetty", reference:"3.6.2+dfsg-10+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"solr-tomcat", reference:"3.6.2+dfsg-10+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
