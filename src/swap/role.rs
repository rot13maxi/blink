use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Hash, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Maker,
    Taker,
}

impl Role {
    fn other(&self) -> Role {
        match self {
            Role::Maker => Role::Taker,
            Role::Taker => Role::Maker,
        }
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "maker" || s == "Maker" {
            Ok(Role::Maker)
        } else if s == "taker" || s == "Taker" {
            Ok(Role::Taker)
        } else {
            Err(())
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Maker => f.write_str("Maker"),
            Role::Taker => f.write_str("Taker"),
        }
    }
}
