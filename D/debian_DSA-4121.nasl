#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4121. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106956);
  script_version("3.2");
  script_cvs_date("Date: 2018/11/10 11:49:39");

  script_xref(name:"DSA", value:"4121");

  script_name(english:"Debian DSA-4121-1 : gcc-6 - security update");
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
    value:"https://packages.debian.org/source/stretch/gcc-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4121"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gcc-6 packages.

For the stable distribution (stretch), this problem has been fixed in
version 6.3.0-18+deb9u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gcc-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/23");
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
if (deb_check(release:"9.0", prefix:"cpp-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"fixincludes", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"g++-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"g++-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-base", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-hppa64-linux-gnu", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-locales", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-plugin-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-source", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcc-6-test-results", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gccgo-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gccgo-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6-jdk", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6-jre", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6-jre-headless", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6-jre-lib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gcj-6-source", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gdc-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gdc-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gfortran-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gfortran-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gnat-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gnat-6-sjlj", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gobjc++-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gobjc++-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gobjc-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gobjc-6-multilib", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32asan3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32asan3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32atomic1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32atomic1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32cilkrts5", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32cilkrts5-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gcc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gcc1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gcc1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gfortran-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gfortran3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gfortran3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32go9", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32go9-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gomp1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gomp1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gphobos-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gphobos68", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32gphobos68-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32itm1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32itm1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32lsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32lsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32mpx2", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32mpx2-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32objc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32objc4", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32objc4-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32quadmath0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32quadmath0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32stdc++-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32stdc++6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32stdc++6-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32ubsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib32ubsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64asan3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64asan3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64atomic1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64atomic1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64cilkrts5", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64cilkrts5-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gcc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gcc1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gcc1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gfortran-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gfortran3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gfortran3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64go9", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64go9-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gomp1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gomp1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gphobos-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gphobos68", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64gphobos68-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64itm1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64itm1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64mpx2", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64mpx2-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64objc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64objc4", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64objc4-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64quadmath0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64quadmath0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64stdc++-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64stdc++6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64stdc++6-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64ubsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"lib64ubsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libasan3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libasan3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatomic1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libatomic1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcc1-0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcilkrts5", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcilkrts5-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcc1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcc1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgccjit-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgccjit-6-doc", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgccjit0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgccjit0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcj-doc", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcj17", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcj17-awt", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcj17-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcj17-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgfortran-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgfortran3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgfortran3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnat-6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnat-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatprj6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatprj6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatprj6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatvsn6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatvsn6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgnatvsn6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgo9", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgo9-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgomp1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgomp1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgphobos-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgphobos68", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgphobos68-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libitm1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libitm1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmpx2", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libmpx2-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32atomic1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32atomic1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gcc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gcc1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gcc1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gfortran-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gfortran3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gfortran3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32go9", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32go9-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gomp1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32gomp1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32objc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32objc4", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32objc4-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32stdc++-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32stdc++6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libn32stdc++6-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libobjc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libobjc4", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libobjc4-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libquadmath0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libquadmath0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstdc++-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstdc++-6-doc", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstdc++-6-pic", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstdc++6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstdc++6-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libubsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libubsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32asan3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32asan3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32atomic1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32atomic1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32cilkrts5", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32cilkrts5-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gcc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gcc1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gcc1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gfortran-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gfortran3", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gfortran3-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32go9", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32go9-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gomp1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gomp1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gphobos-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gphobos68", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32gphobos68-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32itm1", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32itm1-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32lsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32lsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32objc-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32objc4", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32objc4-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32quadmath0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32quadmath0-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32stdc++-6-dev", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32stdc++6", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32stdc++6-6-dbg", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32ubsan0", reference:"6.3.0-18+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libx32ubsan0-dbg", reference:"6.3.0-18+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
