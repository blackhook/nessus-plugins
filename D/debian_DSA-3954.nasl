#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3954. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102790);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10135", "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");
  script_xref(name:"DSA", value:"3954");

  script_name(english:"Debian DSA-3954-1 : openjdk-7 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in sandbox
bypass, incorrect authentication, the execution of arbitrary code,
denial of service, information disclosure, use of insecure
cryptography or bypassing Jar verification."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openjdk-7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3954"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-7 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 7u151-2.6.11-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"8.0", prefix:"icedtea-7-jre-jamvm", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-dbg", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-demo", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-doc", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jdk", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-headless", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-lib", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-zero", reference:"7u151-2.6.11-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-source", reference:"7u151-2.6.11-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
