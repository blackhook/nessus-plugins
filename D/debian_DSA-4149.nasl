#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4149. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108571);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-1000487");
  script_xref(name:"DSA", value:"4149");

  script_name(english:"Debian DSA-4149-1 : plexus-utils2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Charles Duffy discovered that the Commandline class in the utilities
for the Plexus framework performs insufficient quoting of
double-encoded strings, which could result in the execution of
arbitrary shell commands."
  );
  # https://security-tracker.debian.org/tracker/source-package/plexus-utils2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?651018ed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/plexus-utils2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the plexus-utils2 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 3.0.15-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed
prior to the initial release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plexus-utils2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/23");
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
if (deb_check(release:"8.0", prefix:"libplexus-utils2-java", reference:"3.0.15-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libplexus-utils2-java-doc", reference:"3.0.15-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
