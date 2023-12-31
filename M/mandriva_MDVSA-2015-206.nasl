#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:206. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83098);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3008");
  script_bugtraq_id(74022);
  script_xref(name:"MDVSA", value:"2015:206");

  script_name(english:"Mandriva Linux Security Advisory : asterisk (MDVSA-2015:206)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated asterisk packages fix security vulnerability :

When Asterisk registers to a SIP TLS device and and verifies the
server, Asterisk will accept signed certificates that match a common
name other than the one Asterisk is expecting if the signed
certificate has a common name containing a null byte after the portion
of the common name that Asterisk expected (CVE-2015-3008)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0153.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-cel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-corosync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-fax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-festival");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-jabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-minivm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-osp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-pktccops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-portaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-saycountpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-skinny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-speex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-unistim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64asteriskssl1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-addons-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-devel-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-firmware-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-gui-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-alsa-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-calendar-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-cel-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-corosync-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-curl-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-dahdi-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-fax-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-festival-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ices-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-jabber-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-jack-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ldap-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-lua-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-minivm-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mobile-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mp3-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mysql-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ooh323-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-osp-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-oss-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-pgsql-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-pktccops-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-portaudio-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-radius-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-saycountpl-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-skinny-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-snmp-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-speex-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-sqlite-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-tds-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-unistim-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-imap-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-plain-11.17.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64asteriskssl1-11.17.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
