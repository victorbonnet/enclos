//! Messaging channels (design §12): where a runtime's agents answer people,
//! such as a Telegram bot, served by the runtime's own service.

use std::fmt;
use std::str::FromStr;

/// The channels enclos can set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Telegram,
    /// The enclos mobile app, through the host's bridge (ADR 0042,
    /// proposed): no bot of a messaging service, and no host to reach.
    App,
}

impl Channel {
    pub const ALL: [Channel; 2] = [Channel::Telegram, Channel::App];

    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Telegram => "telegram",
            Channel::App => "app",
        }
    }

    /// Its name as people write it.
    pub fn display_name(self) -> &'static str {
        match self {
            Channel::Telegram => "Telegram",
            Channel::App => "enclos app",
        }
    }

    /// The variable its bot's token is read from unless another is named:
    /// Hermes's own, which it keeps out of the commands its agents run
    /// (read in Hermes 0.22.4's `tools/environments/local_env_policy.py`).
    /// In the gateway's environment, it turns the bot on as the gateway
    /// starts, even before `runtime configure` says who it answers.
    pub fn token_variable(self) -> &'static str {
        match self {
            Channel::Telegram => "TELEGRAM_BOT_TOKEN",
            // The agent's token, which the bridge presents to its plugin.
            Channel::App => "MOBILE_APP_TOKEN",
        }
    }

    /// The host its bot reaches, which the policy must allow for the bot
    /// to work; `None` for a channel that reaches out to nothing, as the
    /// app's, which the bridge dials into.
    pub fn host(self) -> Option<&'static str> {
        match self {
            Channel::Telegram => Some("api.telegram.org"),
            Channel::App => None,
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown channel `{0}`: this enclos knows {known}", known = known())]
pub struct UnknownChannel(pub String);

fn known() -> String {
    Channel::ALL
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl FromStr for Channel {
    type Err = UnknownChannel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Channel::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| UnknownChannel(s.to_owned()))
    }
}

/// Someone a channel's bot answers: a Telegram user's numeric id, as
/// Telegram's @userinfobot gives it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelUser(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a Telegram user id: give the number Telegram's @userinfobot shows, not a @name"
)]
pub struct InvalidChannelUser(pub String);

impl ChannelUser {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ChannelUser {
    type Err = InvalidChannelUser;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) {
            true => Ok(ChannelUser(s.to_owned())),
            false => Err(InvalidChannelUser(s.to_owned())),
        }
    }
}

impl fmt::Display for ChannelUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_and_users_parse() {
        assert_eq!("telegram".parse::<Channel>(), Ok(Channel::Telegram));
        assert_eq!("app".parse::<Channel>(), Ok(Channel::App));
        assert_eq!(Channel::App.host(), None);
        assert!("slack".parse::<Channel>().is_err());
        // The policy grants each channel's token as a secret, so its name
        // must be one a policy may grant.
        for channel in Channel::ALL {
            let token = channel.token_variable();
            assert!(!crate::model::secret::reserved_variable(token), "{token}");
        }
        assert_eq!(
            "123456789".parse::<ChannelUser>().unwrap().as_str(),
            "123456789"
        );
        for bad in ["", "@alice", "12 3", "-100123", &"9".repeat(21)] {
            assert!(bad.parse::<ChannelUser>().is_err(), "{bad}");
        }
    }
}
