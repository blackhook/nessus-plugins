#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3861. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100392);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-6891");
  script_xref(name:"DSA", value:"3861");

  script_name(english:"Debian DSA-3861-1 : libtasn1-6 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakub Jirasek of Secunia Research discovered that libtasn1, a library
used to handle Abstract Syntax Notation One structures, did not
properly validate its input. This would allow an attacker to cause a
crash by denial-of-service, or potentially execute arbitrary code, by
tricking a user into processing a maliciously crafted assignments
file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libtasn1-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3861"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libtasn1-6 packages.

For the stable distribution (jessie), this problem has been fixed in
version 4.2-3+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
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
if (deb_check(release:"8.0", prefix:"libtasn1-3-bin", reference:"4.2-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6", reference:"4.2-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dbg", reference:"4.2-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-6-dev", reference:"4.2-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-bin", reference:"4.2-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libtasn1-doc", reference:"4.2-3+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
