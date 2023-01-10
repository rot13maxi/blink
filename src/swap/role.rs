use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Hash, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Initiator,
    Participant,
}

impl Role {
    fn other(&self) -> Role {
        match self {
            Role::Initiator => Role::Participant,
            Role::Participant => Role::Initiator,
        }
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "initiator" || s == "Initiator" || s == "init" {
            Ok(Role::Initiator)
        } else if s == "participant" || s == "Participant" {
            Ok(Role::Participant)
        } else {
            Err(())
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Initiator => f.write_str("Initiator"),
            Role::Participant => f.write_str("Participant"),
        }
    }
}
