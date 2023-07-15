#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1254-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106210);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-12629");
  script_xref(name:"IAVA", value:"2017-A-0319");

  script_name(english:"Debian DLA-1254-1 : lucene-solr security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michael Stepankin and Olga Barinova discovered a remote code execution
vulnerability in Apache Solr by exploiting XML External Entity
processing (XXE) in conjunction with use of a Config API add-listener
command to reach the RunExecutableListener class. To resolve this
issue the RunExecutableListener class has been removed and resolving
of external entities in the CoreParser class disallowed.

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.0+dfsg-1+deb7u3.

We recommend that you upgrade your lucene-solr packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lucene-solr"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblucene3-contrib-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblucene3-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblucene3-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolr-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:solr-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:solr-jetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:solr-tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"liblucene3-contrib-java", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"liblucene3-java", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"liblucene3-java-doc", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libsolr-java", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"solr-common", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"solr-jetty", reference:"3.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"solr-tomcat", reference:"3.6.0+dfsg-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
