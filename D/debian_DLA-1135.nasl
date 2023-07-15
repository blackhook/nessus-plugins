#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1135-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103947);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-10140");

  script_name(english:"Debian DLA-1135-1 : db security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the Berkeley DB reads DB_CONFIG from the current
working directory, leading to information leak by tricking privileged
processes into reading arbitrary files.

For Debian 7 'Wheezy', these problems have been fixed in version
5.1.29-5+deb7u1.

We recommend that you upgrade your db packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/10/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/db"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:db5.1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:db5.1-sql-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:db5.1-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-java-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-java-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-java-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-sql-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-stl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-stl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdb5.1-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"db5.1-doc", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"db5.1-sql-util", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"db5.1-util", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1++", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1++-dev", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-dbg", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-dev", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-java", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-java-dev", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-java-gcj", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-java-jni", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-sql", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-sql-dev", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-stl", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-stl-dev", reference:"5.1.29-5+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libdb5.1-tcl", reference:"5.1.29-5+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");