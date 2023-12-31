#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3144. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81090);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412");
  script_bugtraq_id(70574, 72132, 72136, 72140, 72142, 72155, 72162, 72165, 72168, 72169, 72173, 72175);
  script_xref(name:"DSA", value:"3144");

  script_name(english:"Debian DSA-3144-1 : openjdk-7 - security update (POODLE)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in the execution
of arbitrary code, information disclosure or denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjdk-7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3144"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-7 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 7u75-2.5.4-1~deb7u1.

For the upcoming stable distribution (jessie), these problems will be
fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-cacao", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-jamvm", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-dbg", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-demo", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-doc", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jdk", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-headless", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-lib", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-zero", reference:"7u75-2.5.4-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-source", reference:"7u75-2.5.4-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
