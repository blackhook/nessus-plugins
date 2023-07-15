##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020-12-23 due to Amazon pulling the previsouly published advisory.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1473.
##

include('compat.inc');

if (description)
{
  script_id(144462);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2020-17527");
  script_xref(name:"ALAS", value:"2020-1473");
  script_xref(name:"IAVA", value:"2020-A-0570-S");

  script_name(english:"Amazon Linux AMI : tomcat8 (ALAS-2020-1473) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2020-1473 advisory.

  - While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to
    9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request header value from the previous stream received on
    an HTTP/2 connection for the request associated with the subsequent stream. While this would most likely
    lead to an error and the closure of the HTTP/2 connection, it is possible that information could leak
    between requests. (CVE-2020-17527)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated due to Amazon pulling the previously published advisory.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1473.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-17527");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated due to Amazon pulling the previously published advisory.");
