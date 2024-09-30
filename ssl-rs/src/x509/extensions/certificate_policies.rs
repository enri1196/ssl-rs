use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Debug, Clone)]
pub enum PolicyQualifierInfo {
    CpsUri(String),
    UserNotice(UserNotice),
}

#[derive(Default, Debug, Clone)]
pub struct PolicyInformation {
    pub policy_identifier: String,
    pub policy_qualifiers: Vec<PolicyQualifierInfo>, // Optional
}

impl PolicyInformation {
    pub fn new(policy_identifier: impl Into<String>) -> Self {
        Self {
            policy_identifier: policy_identifier.into(),
            policy_qualifiers: Vec::new(),
        }
    }

    pub fn add_cps_uri(&mut self, cps_uri: impl Into<String>) -> &mut Self {
        self.policy_qualifiers
            .push(PolicyQualifierInfo::CpsUri(cps_uri.into()));
        self
    }

    pub fn add_user_notice(&mut self, user_notice: UserNotice) -> &mut Self {
        self.policy_qualifiers
            .push(PolicyQualifierInfo::UserNotice(user_notice));
        self
    }
}

#[derive(Default, Debug, Clone)]
pub struct UserNotice {
    pub notice_ref: Option<NoticeReference>,
    pub explicit_text: Option<String>, // DisplayText
}

impl UserNotice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_notice_ref(&mut self, notice_ref: NoticeReference) -> &mut Self {
        self.notice_ref = Some(notice_ref);
        self
    }

    pub fn set_explicit_text(&mut self, text: impl Into<String>) -> &mut Self {
        self.explicit_text = Some(text.into());
        self
    }
}

impl Display for UserNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut params = Vec::new();

        if let Some(ref text) = self.explicit_text {
            params.push(format!("explicitText={}", quote_string(text)));
        }

        if let Some(ref notice_ref) = self.notice_ref {
            params.push(format!("{}", notice_ref));
        }

        write!(f, "UserNotice:{}", params.join(","))
    }
}

#[derive(Default, Debug, Clone)]
pub struct NoticeReference {
    pub organization: String, // DisplayText
    pub notice_numbers: Vec<u32>,
}

impl NoticeReference {
    pub fn new(organization: impl Into<String>, notice_numbers: Vec<u32>) -> Self {
        Self {
            organization: organization.into(),
            notice_numbers,
        }
    }
}

impl Display for NoticeReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let numbers = self
            .notice_numbers
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");

        write!(
            f,
            "organization={},noticeNumbers={}",
            quote_string(&self.organization),
            numbers
        )
    }
}

#[derive(Default, Debug, Clone)]
pub struct CertificatePolicies {
    pub critical: bool,
    pub policies: Vec<PolicyInformation>,
}

impl CertificatePolicies {
    pub fn new(critical: bool) -> Self {
        Self {
            critical,
            policies: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: PolicyInformation) -> &mut Self {
        self.policies.push(policy);
        self
    }
}

impl Display for CertificatePolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = String::new();

        if self.critical {
            value.push_str("critical");
        }

        for policy in &self.policies {
            value.push_str(&format!(",policy:{}", policy.policy_identifier));

            for pqi in &policy.policy_qualifiers {
                match pqi {
                    PolicyQualifierInfo::CpsUri(cps_uri) => {
                        value.push_str(&format!(",CPS:{}", cps_uri))
                    }
                    PolicyQualifierInfo::UserNotice(user_notice) => {
                        value.push_str(&format!(",{}", user_notice))
                    }
                }
            }
        }

        write!(f, "{}", value)
    }
}

fn quote_string(s: &str) -> String {
    let escaped = s.replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

impl ToExt for CertificatePolicies {
    fn to_ext(&self) -> X509Ext {
        unsafe {
            let ctx = std::ptr::null_mut();
            X509V3_set_ctx(
                ctx,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            );

            let value = CString::new(self.to_string()).expect("CString Nul error");
            let ext = X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                ctx,
                X509ExtNid::CERTIFICATE_POLICIES.nid(),
                value.as_ptr(),
            );

            X509Ext::from_ptr(ext)
        }
    }
}

#[test]
pub fn test_certificate_policies() {
    let mut cp = CertificatePolicies::new(true);

    let mut policy1 = PolicyInformation::new("1.2.3.4.5.6");
    policy1.add_cps_uri("http://example.com/cps");

    let mut user_notice1 = UserNotice::new();
    user_notice1.set_explicit_text("This is a user notice.");
    policy1.add_user_notice(user_notice1);

    let mut policy2 = PolicyInformation::new("2.3.4.5.6.7");
    policy2.add_cps_uri("http://example.org/cps");

    let mut user_notice2 = UserNotice::new();
    user_notice2.set_explicit_text("Another user notice.");
    policy2.add_user_notice(user_notice2);

    cp.add_policy(policy1);
    cp.add_policy(policy2);

    println!("{cp}");

    // let cp_ext = cp.to_ext();

    // println!("OID: {}", cp_ext.get_oid());
    // println!("DATA: {}", cp.to_string());

    // assert_eq!("2.5.29.32", cp_ext.get_oid());
}
