#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4570. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131087);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-11779");
  script_xref(name:"DSA", value:"4570");

  script_name(english:"Debian DSA-4570-1 : mosquitto - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered in mosquitto, a MQTT version 3.1/3.1.1
compatible message broker, allowing a malicious MQTT client to cause a
denial of service (stack overflow and daemon crash), by sending a
specially crafted SUBSCRIBE packet containing a topic with a extremely
deep hierarchy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=940654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/mosquitto"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/mosquitto"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4570"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mosquitto packages.

For the stable distribution (buster), this problem has been fixed in
version 1.5.7-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");
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
if (deb_check(release:"10.0", prefix:"libmosquitto-dev", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmosquitto1", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmosquittopp-dev", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmosquittopp1", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mosquitto", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mosquitto-clients", reference:"1.5.7-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"mosquitto-dev", reference:"1.5.7-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
