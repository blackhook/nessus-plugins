#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3077. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79586);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_bugtraq_id(70533, 70538, 70544, 70548, 70552, 70556, 70564, 70567, 70570, 70572);
  script_xref(name:"DSA", value:"3077");

  script_name(english:"Debian DSA-3077-1 : openjdk-6 - security update");
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
    value:"https://packages.debian.org/source/wheezy/openjdk-6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2014/dsa-3077"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openjdk-6 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 6b33-1.13.5-2~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-cacao", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-6-jre-jamvm", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-dbg", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-demo", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-doc", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jdk", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-headless", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-lib", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-jre-zero", reference:"6b33-1.13.5-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-6-source", reference:"6b33-1.13.5-2~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
