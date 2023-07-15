#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4174. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109092);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/01");

  script_cve_id("CVE-2018-1084");
  script_xref(name:"DSA", value:"4174");

  script_name(english:"Debian DSA-4174-1 : corosync - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Citrix Security Response Team discovered that corosync, a cluster
engine implementation, allowed an unauthenticated user to cause a
denial-of-service by application crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=895653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/corosync"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/corosync"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4174"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the corosync packages.

For the stable distribution (stretch), this problem has been fixed in
version 2.4.2-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:corosync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"corosync", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"corosync-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"corosync-doc", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"corosync-notifyd", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"corosync-qdevice", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"corosync-qnetd", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcfg-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcfg6", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcmap-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcmap4", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcorosync-common-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcorosync-common4", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpg-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcpg4", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libquorum-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libquorum5", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsam-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsam4", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtotem-pg-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtotem-pg5", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvotequorum-dev", reference:"2.4.2-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvotequorum8", reference:"2.4.2-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
