#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1633-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121133);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-10989", "CVE-2017-2518", "CVE-2017-2519", "CVE-2017-2520", "CVE-2018-8740");

  script_name(english:"Debian DLA-1633-1 : sqlite3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were corrected in SQLite, a SQL database engine.

CVE-2017-2518

A use-after-free bug in the query optimizer may cause a buffer
overflow and application crash via a crafted SQL statement.

CVE-2017-2519

Insufficient size of the reference count on Table objects could lead
to a denial of service or arbitrary code execution.

CVE-2017-2520

The sqlite3_value_text() interface returned a buffer that was not
large enough to hold the complete string plus zero terminator when the
input was a zeroblob. This could lead to arbitrary code execution or a
denial of service.

CVE-2017-10989

SQLite mishandles undersized RTree blobs in a crafted database leading
to a heap-based buffer over-read or possibly unspecified other impact.

CVE-2018-8740

Databases whose schema is corrupted using a CREATE TABLE AS statement
could cause a NULL pointer dereference.

For Debian 8 'Jessie', these problems have been fixed in version
3.8.7.1-1+deb8u4.

We recommend that you upgrade your sqlite3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/sqlite3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sqlite3-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"lemon", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsqlite3-0", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsqlite3-0-dbg", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsqlite3-dev", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsqlite3-tcl", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"sqlite3", reference:"3.8.7.1-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"sqlite3-doc", reference:"3.8.7.1-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
