#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4160. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108772);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/18");

  script_cve_id("CVE-2018-8754");
  script_xref(name:"DSA", value:"4160");

  script_name(english:"Debian DSA-4160-1 : libevt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that insufficient input sanitising in libevt, a
library to access the Windows Event Log (EVT) format, could result in
denial of service if a malformed EVT file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/libevt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libevt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4160"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the libevt packages.

For the stable distribution (stretch), this problem has been fixed in
version 20170120-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libevt-dbg", reference:"20170120-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libevt-dev", reference:"20170120-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libevt-utils", reference:"20170120-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libevt1", reference:"20170120-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-libevt", reference:"20170120-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libevt", reference:"20170120-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
