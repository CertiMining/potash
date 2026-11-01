// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure identity-separation checks for the split anchoring deployment (D-143).
//!
//! The deployment preflight reads keys, but the decision is kept here so negative tests can prove
//! each collision is rejected without opening a key file or reaching a network.

/// A public or private identity in the anchoring deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    ProgramAddress,
    DeployAuthority,
    WorkerPayer,
    CheckpointAuthority,
    BatcherSigning,
    MasterKey,
}

/// Two roles collapsed onto the same public identity or private seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCollision {
    Public { left: KeyRole, right: KeyRole },
    Secret { left: KeyRole, right: KeyRole },
}

/// Refuses any duplicate in the supplied public identities or private seeds.
///
/// Callers supply only secrets present on the current host. Split-host absence is enforced by the
/// preflight binary; this function establishes that any secrets that are present are not reused.
pub fn verify_role_separation(
    public: &[(KeyRole, [u8; 32])],
    secrets: &[(KeyRole, [u8; 32])],
) -> Result<(), KeyCollision> {
    for (index, (left_role, left)) in public.iter().enumerate() {
        for (right_role, right) in public.iter().skip(index.saturating_add(1)) {
            if left == right {
                return Err(KeyCollision::Public {
                    left: *left_role,
                    right: *right_role,
                });
            }
        }
    }
    for (index, (left_role, left)) in secrets.iter().enumerate() {
        for (right_role, right) in secrets.iter().skip(index.saturating_add(1)) {
            if left == right {
                return Err(KeyCollision::Secret {
                    left: *left_role,
                    right: *right_role,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_roles_pass() {
        let public = [
            (KeyRole::ProgramAddress, [1; 32]),
            (KeyRole::DeployAuthority, [2; 32]),
            (KeyRole::WorkerPayer, [3; 32]),
            (KeyRole::CheckpointAuthority, [4; 32]),
            (KeyRole::BatcherSigning, [5; 32]),
        ];
        let secrets = [
            (KeyRole::MasterKey, [6; 32]),
            (KeyRole::BatcherSigning, [7; 32]),
        ];
        assert_eq!(verify_role_separation(&public, &secrets), Ok(()));
    }

    #[test]
    fn public_identity_collapse_is_refused() {
        let public = [
            (KeyRole::WorkerPayer, [3; 32]),
            (KeyRole::CheckpointAuthority, [3; 32]),
        ];
        assert_eq!(
            verify_role_separation(&public, &[]),
            Err(KeyCollision::Public {
                left: KeyRole::WorkerPayer,
                right: KeyRole::CheckpointAuthority,
            })
        );
    }

    #[test]
    fn secret_reuse_is_refused_without_disclosing_the_value() {
        let secrets = [
            (KeyRole::MasterKey, [9; 32]),
            (KeyRole::BatcherSigning, [9; 32]),
        ];
        assert_eq!(
            verify_role_separation(&[], &secrets),
            Err(KeyCollision::Secret {
                left: KeyRole::MasterKey,
                right: KeyRole::BatcherSigning,
            })
        );
    }
}
