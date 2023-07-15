#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3794. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97398);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-6188");
  script_xref(name:"DSA", value:"3794");

  script_name(english:"Debian DSA-3794-1 : munin - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Stevie Trujillo discovered a local file write vulnerability in munin,
a network-wide graphing framework, when CGI graphs are enabled. GET
parameters are not properly handled, allowing to inject options into
munin-cgi-graph and overwriting any file accessible by the user
running the cgi-process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=855705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/munin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3794"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the munin packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.0.25-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");
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
if (deb_check(release:"8.0", prefix:"munin", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-async", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-common", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-doc", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-node", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-plugins-core", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-plugins-extra", reference:"2.0.25-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"munin-plugins-java", reference:"2.0.25-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
