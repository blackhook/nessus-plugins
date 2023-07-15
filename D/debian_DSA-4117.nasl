#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4117. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106875);
  script_version("3.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_xref(name:"DSA", value:"4117");

  script_name(english:"Debian DSA-4117-1 : gcc-4.9 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update doesn't fix a vulnerability in GCC itself, but instead
provides support for building retpoline-enabled Linux kernel updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/gcc-4.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gcc-4.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4117"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gcc-4.9 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 4.9.2-10+deb8u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gcc-4.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
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
if (deb_check(release:"8.0", prefix:"cpp-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fixincludes", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"g++-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"g++-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9-base", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9-locales", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9-plugin-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcc-4.9-source", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gccgo-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gccgo-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9-jdk", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9-jre", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9-jre-headless", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9-jre-lib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gcj-4.9-source", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gdc-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gfortran-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gfortran-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gobjc++-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gobjc++-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gobjc-4.9", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gobjc-4.9-multilib", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32asan1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32asan1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32atomic1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32atomic1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32cilkrts5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32cilkrts5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gcc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gcc1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gcc1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gfortran-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gfortran3", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gfortran3-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32go5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32go5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gomp1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32gomp1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32itm1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32itm1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32lsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32lsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32objc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32objc4", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32objc4-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32quadmath0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32quadmath0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32stdc++-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32stdc++6", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32stdc++6-4.9-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32ubsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib32ubsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64asan1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64asan1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64atomic1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64atomic1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64cilkrts5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64cilkrts5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gcc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gcc1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gcc1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gfortran-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gfortran3", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gfortran3-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64go5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64go5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gomp1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64gomp1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64itm1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64itm1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64objc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64objc4", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64objc4-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64quadmath0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64quadmath0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64stdc++-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64stdc++6", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64stdc++6-4.9-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64ubsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"lib64ubsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libasan1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libasan1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatomic1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libatomic1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcilkrts5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libcilkrts5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcc1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcc1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcj-doc", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcj15", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcj15-awt", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcj15-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgcj15-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgfortran-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgfortran3", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgfortran3-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgo5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgo5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgomp1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgomp1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libitm1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libitm1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"liblsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"liblsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32atomic1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32atomic1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gcc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gcc1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gcc1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gfortran-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gfortran3", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gfortran3-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32go5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32go5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gomp1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32gomp1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32objc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32objc4", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32objc4-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32stdc++-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32stdc++6", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libn32stdc++6-4.9-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libobjc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libobjc4", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libobjc4-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libphobos-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libquadmath0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libquadmath0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libstdc++-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libstdc++-4.9-doc", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libstdc++-4.9-pic", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libstdc++6", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libstdc++6-4.9-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libtsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libubsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libubsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32asan1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32asan1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32atomic1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32atomic1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32cilkrts5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32cilkrts5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gcc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gcc1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gcc1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gfortran-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gfortran3", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gfortran3-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32go5", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32go5-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gomp1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32gomp1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32itm1", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32itm1-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32lsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32lsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32objc-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32objc4", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32objc4-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32quadmath0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32quadmath0-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32stdc++-4.9-dev", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32stdc++6", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32stdc++6-4.9-dbg", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32ubsan0", reference:"4.9.2-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libx32ubsan0-dbg", reference:"4.9.2-10+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
