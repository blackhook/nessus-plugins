#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6518. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165092);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2021-2478",
    "CVE-2021-2479",
    "CVE-2021-2481",
    "CVE-2021-35546",
    "CVE-2021-35575",
    "CVE-2021-35577",
    "CVE-2021-35591",
    "CVE-2021-35596",
    "CVE-2021-35597",
    "CVE-2021-35602",
    "CVE-2021-35604",
    "CVE-2021-35607",
    "CVE-2021-35608",
    "CVE-2021-35610",
    "CVE-2021-35612",
    "CVE-2021-35622",
    "CVE-2021-35623",
    "CVE-2021-35624",
    "CVE-2021-35625",
    "CVE-2021-35626",
    "CVE-2021-35627",
    "CVE-2021-35628",
    "CVE-2021-35630",
    "CVE-2021-35631",
    "CVE-2021-35632",
    "CVE-2021-35633",
    "CVE-2021-35634",
    "CVE-2021-35635",
    "CVE-2021-35636",
    "CVE-2021-35637",
    "CVE-2021-35638",
    "CVE-2021-35639",
    "CVE-2021-35640",
    "CVE-2021-35641",
    "CVE-2021-35642",
    "CVE-2021-35643",
    "CVE-2021-35644",
    "CVE-2021-35645",
    "CVE-2021-35646",
    "CVE-2021-35647",
    "CVE-2021-35648",
    "CVE-2022-21245",
    "CVE-2022-21249",
    "CVE-2022-21253",
    "CVE-2022-21254",
    "CVE-2022-21256",
    "CVE-2022-21264",
    "CVE-2022-21265",
    "CVE-2022-21270",
    "CVE-2022-21278",
    "CVE-2022-21297",
    "CVE-2022-21301",
    "CVE-2022-21302",
    "CVE-2022-21303",
    "CVE-2022-21304",
    "CVE-2022-21339",
    "CVE-2022-21342",
    "CVE-2022-21344",
    "CVE-2022-21348",
    "CVE-2022-21351",
    "CVE-2022-21352",
    "CVE-2022-21358",
    "CVE-2022-21362",
    "CVE-2022-21367",
    "CVE-2022-21368",
    "CVE-2022-21370",
    "CVE-2022-21372",
    "CVE-2022-21374",
    "CVE-2022-21378",
    "CVE-2022-21379",
    "CVE-2022-21412",
    "CVE-2022-21413",
    "CVE-2022-21414",
    "CVE-2022-21415",
    "CVE-2022-21417",
    "CVE-2022-21418",
    "CVE-2022-21423",
    "CVE-2022-21425",
    "CVE-2022-21427",
    "CVE-2022-21435",
    "CVE-2022-21436",
    "CVE-2022-21437",
    "CVE-2022-21438",
    "CVE-2022-21440",
    "CVE-2022-21444",
    "CVE-2022-21451",
    "CVE-2022-21452",
    "CVE-2022-21454",
    "CVE-2022-21455",
    "CVE-2022-21457",
    "CVE-2022-21459",
    "CVE-2022-21460",
    "CVE-2022-21462",
    "CVE-2022-21478",
    "CVE-2022-21479",
    "CVE-2022-21509",
    "CVE-2022-21515",
    "CVE-2022-21517",
    "CVE-2022-21522",
    "CVE-2022-21525",
    "CVE-2022-21526",
    "CVE-2022-21527",
    "CVE-2022-21528",
    "CVE-2022-21529",
    "CVE-2022-21530",
    "CVE-2022-21531",
    "CVE-2022-21534",
    "CVE-2022-21537",
    "CVE-2022-21538",
    "CVE-2022-21539",
    "CVE-2022-21547",
    "CVE-2022-21553",
    "CVE-2022-21556",
    "CVE-2022-21569"
  );
  script_xref(name:"RHSA", value:"2022:6518");

  script_name(english:"RHEL 7 : rh-mysql80-mysql (RHSA-2022:6518)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:6518 advisory.

  - mysql: Server: DML unspecified vulnerability (CPU Oct 2021) (CVE-2021-2478, CVE-2021-2479, CVE-2021-35591,
    CVE-2021-35607)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2021) (CVE-2021-2481, CVE-2021-35575,
    CVE-2021-35577, CVE-2021-35610, CVE-2021-35612, CVE-2021-35626, CVE-2021-35627, CVE-2021-35628,
    CVE-2021-35634, CVE-2021-35635, CVE-2021-35636, CVE-2021-35638, CVE-2021-35641, CVE-2021-35642,
    CVE-2021-35643, CVE-2021-35644, CVE-2021-35645, CVE-2021-35646, CVE-2021-35647)

  - mysql: Server: Replication unspecified vulnerability (CPU Oct 2021) (CVE-2021-35546)

  - mysql: Server: Error Handling unspecified vulnerability (CPU Oct 2021) (CVE-2021-35596)

  - mysql: C API unspecified vulnerability (CPU Oct 2021) (CVE-2021-35597)

  - mysql: Server: Options unspecified vulnerability (CPU Oct 2021) (CVE-2021-35602, CVE-2021-35630)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2021) (CVE-2021-35604)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Oct 2021) (CVE-2021-35608)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2021) (CVE-2021-35622)

  - mysql: Server: Security: Roles unspecified vulnerability (CPU Oct 2021) (CVE-2021-35623)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2021) (CVE-2021-35624,
    CVE-2021-35625)

  - mysql: Server: GIS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35631)

  - mysql: Server: Data Dictionary unspecified vulnerability (CPU Oct 2021) (CVE-2021-35632)

  - mysql: Server: Logging unspecified vulnerability (CPU Oct 2021) (CVE-2021-35633)

  - mysql: Server: PS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35637)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2021) (CVE-2021-35639)

  - mysql: Server: DDL unspecified vulnerability (CPU Oct 2021) (CVE-2021-35640)

  - mysql: Server: FTS unspecified vulnerability (CPU Oct 2021) (CVE-2021-35648)

  - mysql: Server: Security: Privileges unspecified vulnerability (CPU Jan 2022) (CVE-2022-21245)

  - mysql: Server: DDL unspecified vulnerability (CPU Jan 2022) (CVE-2022-21249)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2022) (CVE-2022-21253, CVE-2022-21254,
    CVE-2022-21264, CVE-2022-21265, CVE-2022-21278, CVE-2022-21297, CVE-2022-21339, CVE-2022-21342,
    CVE-2022-21351, CVE-2022-21370, CVE-2022-21378)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Jan 2022) (CVE-2022-21256,
    CVE-2022-21379)

  - mysql: Server: Federated unspecified vulnerability (CPU Jan 2022) (CVE-2022-21270)

  - mysql: Server: DML unspecified vulnerability (CPU Jan 2022) (CVE-2022-21301)

  - mysql: InnoDB unspecified vulnerability (CPU Jan 2022) (CVE-2022-21302, CVE-2022-21348, CVE-2022-21352)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jan 2022) (CVE-2022-21303)

  - mysql: Server: Parser unspecified vulnerability (CPU Jan 2022) (CVE-2022-21304)

  - mysql: Server: Replication unspecified vulnerability (CPU Jan 2022) (CVE-2022-21344)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2022) (CVE-2022-21358,
    CVE-2022-21372)

  - mysql: Server: Information Schema unspecified vulnerability (CPU Jan 2022) (CVE-2022-21362,
    CVE-2022-21374)

  - mysql: Server: Compiling unspecified vulnerability (CPU Jan 2022) (CVE-2022-21367)

  - mysql: Server: Components Services unspecified vulnerability (CPU Jan 2022) (CVE-2022-21368)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2022) (CVE-2022-21412, CVE-2022-21414,
    CVE-2022-21435, CVE-2022-21436, CVE-2022-21437, CVE-2022-21438, CVE-2022-21440, CVE-2022-21452,
    CVE-2022-21459, CVE-2022-21462, CVE-2022-21478, CVE-2022-21479)

  - mysql: Server: DML unspecified vulnerability (CPU Apr 2022) (CVE-2022-21413)

  - mysql: Server: Replication unspecified vulnerability (CPU Apr 2022) (CVE-2022-21415)

  - mysql: InnoDB unspecified vulnerability (CPU Apr 2022) (CVE-2022-21417, CVE-2022-21418, CVE-2022-21423,
    CVE-2022-21451)

  - mysql: Server: DDL unspecified vulnerability (CPU Apr 2022) (CVE-2022-21425, CVE-2022-21444)

  - mysql: Server: FTS unspecified vulnerability (CPU Apr 2022) (CVE-2022-21427)

  - mysql: Server: Group Replication Plugin unspecified vulnerability (CPU Apr 2022) (CVE-2022-21454)

  - mysql: Server: PAM Auth Plugin unspecified vulnerability (CPU Jul 2022) (CVE-2022-21455)

  - mysql: Server: PAM Auth Plugin unspecified vulnerability (CPU Apr 2022) (CVE-2022-21457)

  - mysql: Server: Logging unspecified vulnerability (CPU Apr 2022) (CVE-2022-21460)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jul 2022) (CVE-2022-21509, CVE-2022-21525,
    CVE-2022-21526, CVE-2022-21527, CVE-2022-21528, CVE-2022-21529, CVE-2022-21530, CVE-2022-21531,
    CVE-2022-21553, CVE-2022-21556, CVE-2022-21569)

  - mysql: Server: Options unspecified vulnerability (CPU Jul 2022) (CVE-2022-21515)

  - mysql: InnoDB unspecified vulnerability (CPU Jul 2022) (CVE-2022-21517, CVE-2022-21537, CVE-2022-21539)

  - mysql: Server: Stored Procedure unspecified vulnerability (CPU Jul 2022) (CVE-2022-21522, CVE-2022-21534)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Jul 2022) (CVE-2022-21538)

  - mysql: Server: Federated unspecified vulnerability (CPU Jul 2022) (CVE-2022-21547)

  - mysql: Server: Security: Encryption unspecified vulnerability (CPU Oct 2022) (CVE-2022-21592)

  - mysql: C API unspecified vulnerability (CPU Oct 2022) (CVE-2022-21595)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21600, CVE-2022-21607,
    CVE-2022-21638, CVE-2022-21641)

  - mysql: Server: Data Dictionary unspecified vulnerability (CPU Oct 2022) (CVE-2022-21605)

  - mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21635)

  - mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21866, CVE-2023-21872)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2478");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2479");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-2481");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35546");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35575");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35577");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35591");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35596");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35597");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35602");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35604");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35610");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35612");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35622");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35624");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35626");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35627");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35628");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35630");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35631");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35634");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35646");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-35648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21245");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21249");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21253");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21254");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21256");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21264");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21265");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21270");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21278");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21297");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21301");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21302");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21303");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21304");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21339");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21342");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21344");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21348");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21362");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21367");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21368");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21370");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21372");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21378");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21379");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21412");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21413");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21414");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21415");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21417");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21418");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21423");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21425");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21435");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21436");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21437");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21438");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21440");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21444");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21451");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21452");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21454");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21457");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21459");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21460");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21462");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21478");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21479");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21509");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21515");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21517");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21522");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21525");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21526");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21527");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21528");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21529");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21530");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21531");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21534");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21537");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21538");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21539");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21547");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21553");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21556");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21592");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21595");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21600");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21605");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21866");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-21872");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2043648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2082659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2142878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2162279");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-icu-data-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql80-mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mysql80-mysql-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-common-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-config-syspaths-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-devel-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-errmsg-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-icu-data-files-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-server-syspaths-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-syspaths-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.30-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.30-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql80-mysql-test-8.0.30-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mysql80-mysql / rh-mysql80-mysql-common / rh-mysql80-mysql-config / etc');
}
