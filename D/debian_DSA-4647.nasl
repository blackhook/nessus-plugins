#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4647. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(134984);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/28");

  script_cve_id("CVE-2020-0556");
  script_xref(name:"DSA", value:"4647");

  script_name(english:"Debian DSA-4647-1 : bluez - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was reported that the BlueZ's HID and HOGP profile implementations
don't specifically require bonding between the device and the host.
Malicious devices can take advantage of this flaw to connect to a
target host and impersonate an existing HID device without security or
to cause an SDP or GATT service discovery to take place which would
allow HID reports to be injected to the input subsystem from a
non-bonded source.

For the HID profile an new configuration option (ClassicBondedOnly) is
introduced to make sure that input connections only come from bonded
device connections. The options defaults to 'false' to maximize device
compatibility."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=953770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/bluez"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bluez packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 5.43-2+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 5.50-1.2~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0556");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"bluetooth", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez-cups", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez-hcidump", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez-obexd", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez-test-scripts", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"bluez-test-tools", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libbluetooth-dev", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libbluetooth3", reference:"5.50-1.2~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"bluetooth", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-cups", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-dbg", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-hcidump", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-obexd", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-scripts", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"bluez-test-tools", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth-dev", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3", reference:"5.43-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libbluetooth3-dbg", reference:"5.43-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
