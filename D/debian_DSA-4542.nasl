#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4542. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129597);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2019-12384", "CVE-2019-14439", "CVE-2019-14540", "CVE-2019-16335", "CVE-2019-16942", "CVE-2019-16943");
  script_xref(name:"DSA", value:"4542");

  script_name(english:"Debian DSA-4542-1 : jackson-databind - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that jackson-databind, a Java library used to parse
JSON and other data formats, did not properly validate user input
before attempting deserialization. This allowed an attacker providing
maliciously crafted input to perform code execution, or read arbitrary
files on the server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=941530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=940498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=933393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=930750"
  );
  # https://security-tracker.debian.org/tracker/source-package/jackson-databind
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61134ddf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/jackson-databind"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/jackson-databind"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4542"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the jackson-databind packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 2.8.6-1+deb9u6.

For the stable distribution (buster), these problems have been fixed
in version 2.9.8-3+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jackson-databind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"libjackson2-databind-java", reference:"2.9.8-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libjackson2-databind-java-doc", reference:"2.9.8-3+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjackson2-databind-java", reference:"2.8.6-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libjackson2-databind-java-doc", reference:"2.8.6-1+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
